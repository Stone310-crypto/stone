// ─── Swarm-Task ───────────────────────────────────────────────────────────────

use crate::blockchain::Block;
use crate::consensus::verify_block_signature_standalone;
use futures_util::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    autonat,
    dcutr,
    gossipsub::{self, IdentTopic},
    identify,
    kad,
    relay,
    request_response,
    swarm::SwarmEvent,
    upnp,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc};

use super::*;

/// Zustand des laufenden Swarm-Tasks.
pub(crate) struct SwarmTask {
    pub(crate) swarm: Swarm<StoneBehaviour>,
    pub(crate) event_tx: broadcast::Sender<NetworkEvent>,
    pub(crate) cmd_rx: mpsc::Receiver<NetworkCommand>,

    /// Bekannte Peers: PeerId → PeerInfo
    pub(crate) peers: HashMap<PeerId, PeerInfo>,

    /// Seen-Cache: Block-Hashes die bereits verarbeitet wurden (Duplicate-Filter).
    pub(crate) seen_hashes: HashSet<String>,
    pub(crate) seen_order: VecDeque<String>,

    /// Unsere aktuelle Chain-Länge (für Sync-Handshake)
    pub(crate) local_chain_count: u64,

    /// Bootstrap-Adressen für Reconnect
    pub(crate) bootstrap_addrs: Vec<String>,

    /// Zeitpunkt des letzten Reconnect-Versuchs
    pub(crate) last_reconnect: Instant,

    pub(crate) config: P2pConfig,

    /// Ausstehende Pings: request_id → (peer_id_str, start_instant, reply_channel)
    pub(crate) pending_pings: HashMap<
        request_response::OutboundRequestId,
        (String, std::time::Instant, tokio::sync::oneshot::Sender<PingResult>),
    >,

    // ─── NAT-Traversal Zustand ──────────────────────────────────────────────

    /// Erkannter NAT-Status
    pub(crate) nat_status: NatStatus,

    /// Relay-Nodes bei denen wir eine Reservation haben
    pub(crate) active_relays: HashSet<PeerId>,

    /// Relay-Adressen die wir versuchen sollen
    pub(crate) relay_addrs: Vec<String>,

    // ─── Sicherheit: Peer-Scoring ───────────────────────────────────────────

    /// Penalty-Score pro Peer: wenn > BAN_THRESHOLD → Peer wird gebannt
    pub(crate) peer_penalties: HashMap<PeerId, PeerPenalty>,

    // ─── P2P Rate Limiting ──────────────────────────────────────────────────

    /// Token-Bucket Rate Limiter pro Peer (DDoS-Protection)
    pub(crate) peer_rate_limiters: HashMap<PeerId, PeerRateLimiter>,

    // ─── Chain-Referenz für Block-Serving ────────────────────────────────────

    /// Optionale Referenz auf die Chain — wird nach Start per Command injiziert.
    /// Ermöglicht dem SwarmTask Blöcke direkt aus der lokalen Chain zu servieren.
    pub(crate) chain_ref: Option<std::sync::Arc<std::sync::Mutex<crate::blockchain::StoneChain>>>,

    /// Shard-Speicher für eingehende Shard-Requests
    pub(crate) shard_store: crate::shard::ShardStore,

    /// Ausstehende Shard-Listen-Anfragen: request_id → reply
    pub(crate) pending_shard_lists: HashMap<
        request_response::OutboundRequestId,
        (String, tokio::sync::oneshot::Sender<Vec<u8>>),
    >,

    // ─── Netzwerk-Metriken ──────────────────────────────────────────────────

    /// Kumulative Traffic-Metriken
    pub(crate) net_metrics: NetworkMetrics,
    /// Zeitpunkt des Swarm-Starts (für Uptime-Berechnung)
    pub(crate) started_at: Instant,

    // ─── Peer-Storage-Tracking ──────────────────────────────────────────────

    /// Speicher-Ankündigungen von Peers: PeerId-String → StorageAnnouncement
    pub(crate) peer_storage: HashMap<String, StorageAnnouncement>,

    /// Ausstehende ChainInfo-Anfragen: request_id → PeerId
    /// Wird verwendet um die Antwort dem richtigen Peer zuzuordnen und Sync auszulösen.
    pub(crate) pending_chain_info: HashMap<request_response::OutboundRequestId, PeerId>,

    /// Sync-Buffer: Sammelt Blöcke aus parallelen Range-Responses und fügt sie
    /// geordnet ein. Key = Block-Index für schnellen Lookup.
    pub(crate) sync_buffer: std::collections::BTreeMap<u64, (Block, String)>,
    /// Zeitpunkt als zuletzt Blöcke in den sync_buffer kamen (für Flush-Timeout)
    pub(crate) sync_buffer_last_insert: Option<Instant>,
    /// Erwarteter nächster Block-Index für den Sync (= unsere Chain-Höhe beim Sync-Start)
    pub(crate) sync_expected_next: u64,

    // ─── Stake-basierte Relay-Priorität ──────────────────────────────────

    /// Eigener Stake-Level (wird von MasterNode periodisch gesetzt).
    /// 0=Observer, 100=Participant, 250=Guardian, 500=Validator
    pub(crate) local_stake_level: u64,

    // ─── Reconnect-Backoff ───────────────────────────────────────────────

    /// Per-Peer exponentieller Backoff für Reconnect-Versuche.
    /// PeerId → (frühester nächster Versuch, aktueller Backoff-Intervall)
    /// Verhindert Connect-Disconnect-Storms wenn beide Seiten gleichzeitig dialen.
    pub(crate) reconnect_backoff: HashMap<PeerId, (Instant, Duration)>,

    // ─── Keepalive / Warm Peer Table ─────────────────────────────────────

    /// Laufende Keepalive-Pings: request_id → (PeerId, Sende-Zeitpunkt)
    /// Fire-and-forget: kein oneshot-Channel, nur Latenz-Recording.
    pub(crate) keepalive_pings: HashMap<request_response::OutboundRequestId, (PeerId, Instant)>,

    /// Rolling-Window Latenz-Historie pro Peer (letzte 10 Messungen, in ms)
    pub(crate) peer_latencies: HashMap<PeerId, VecDeque<u64>>,

    /// Grace-Zähler für aufeinanderfolgende Rate-Limit-Verletzungen pro Peer.
    /// Erst nach RATE_LIMIT_GRACE Verletzungen wird eine Penalty vergeben.
    pub(crate) rate_limit_grace: HashMap<PeerId, u32>,
}

/// Tracking für Fehlverhalten eines Peers
pub(crate) struct PeerPenalty {
    score: u32,
    last_offense: Instant,
    reasons: Vec<String>,
    /// Wie oft dieser Peer bereits gebannt wurde (für eskalierende Ban-Dauer)
    ban_count: u32,
}

/// Ab diesem Score wird ein Peer gebannt (Verbindung getrennt, kein Re-Dial)
const BAN_THRESHOLD: u32 = 200;

/// Penalty-Punkte verfallen nach dieser Zeit (Minuten)
const PENALTY_DECAY_MINS: u64 = 30;

/// Aufeinanderfolgende Rate-Limit-Verletzungen bevor Penalty vergeben wird
const RATE_LIMIT_GRACE: u32 = 5;

// ─── Persistierte Ban-Liste ───────────────────────────────────────────────────

/// Eintrag in der persistierten Ban-Liste
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BannedPeerEntry {
    peer_id: String,
    score: u32,
    reasons: Vec<String>,
    banned_at: i64,
    /// Unix-Timestamp wann der Ban abläuft (0 = nach Decay)
    expires_at: i64,
    /// Wie oft dieser Peer bereits gebannt wurde
    #[serde(default)]
    ban_count: u32,
    /// Letzte bekannte Adressen (IP/Multiaddr) zum Ban-Zeitpunkt
    #[serde(default)]
    last_known_addresses: Vec<String>,
    /// Agent-Version des Peers (z.B. "stone/0.4.1")
    #[serde(default)]
    agent_version: String,
    /// Menschenlesbare Ban-Dauer (z.B. "2h", "24h")
    #[serde(default)]
    ban_duration: String,
}

/// Lädt die Ban-Liste aus `stone_data/banned_peers.json`
pub(crate) fn load_banned_peers() -> HashMap<PeerId, PeerPenalty> {
    let path = format!("{}/{}", data_dir(), BANNED_PEERS_FILENAME);
    let Ok(data) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    let Ok(entries) = serde_json::from_str::<Vec<BannedPeerEntry>>(&data) else {
        eprintln!("[p2p] ⚠ Konnte Ban-Liste nicht parsen: {path}");
        return HashMap::new();
    };
    let now = chrono::Utc::now().timestamp();
    let mut map = HashMap::new();
    for entry in entries {
        // Abgelaufene Bans überspringen
        if entry.expires_at > 0 && entry.expires_at < now {
            continue;
        }
        if let Ok(peer_id) = entry.peer_id.parse::<PeerId>() {
            map.insert(peer_id, PeerPenalty {
                score: entry.score,
                last_offense: Instant::now(), // konservativ: als "gerade passiert" behandeln
                reasons: entry.reasons,
                ban_count: entry.ban_count,
            });
        }
    }
    if !map.is_empty() {
        println!("[p2p] 🔨 {} gebannte Peers aus Datei geladen", map.len());
    }
    map
}

/// Formatiert Sekunden als menschenlesbare Dauer (z.B. "2h 30m", "24h")
fn format_ban_duration(secs: i64) -> String {
    if secs <= 0 { return "0m".into(); }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    if h > 0 && m > 0 { format!("{h}h {m:02}m") }
    else if h > 0 { format!("{h}h") }
    else { format!("{m}m") }
}

/// Speichert die aktuelle Ban-Liste nach `stone_data/banned_peers.json`
fn save_banned_peers_with_context(
    penalties: &HashMap<PeerId, PeerPenalty>,
    peers: &HashMap<PeerId, PeerInfo>,
) {
    let now = chrono::Utc::now().timestamp();
    let base_ban_secs = (PENALTY_DECAY_MINS * 60 * 2) as i64; // 1 Stunde Basis
    let entries: Vec<BannedPeerEntry> = penalties
        .iter()
        .filter(|(_, p)| p.score >= BAN_THRESHOLD)
        .map(|(peer_id, p)| {
            // Eskalierende Ban-Dauer: base × 2^ban_count (max 24h)
            let escalated = base_ban_secs * (1i64 << p.ban_count.min(5));
            let max_ban = 24 * 60 * 60; // 24 Stunden Maximum
            let ban_secs = escalated.min(max_ban);
            // Peer-Metadaten vom Zeitpunkt des Bans
            let (addrs, agent) = peers.get(peer_id)
                .map(|info| (
                    info.addresses.clone(),
                    info.agent_version.clone(),
                ))
                .unwrap_or_default();
            BannedPeerEntry {
                peer_id: peer_id.to_string(),
                score: p.score,
                reasons: p.reasons.clone(),
                banned_at: now,
                expires_at: now + ban_secs,
                ban_count: p.ban_count,
                last_known_addresses: addrs,
                agent_version: agent,
                ban_duration: format_ban_duration(ban_secs),
            }
        })
        .collect();
    let path = format!("{}/{}", data_dir(), BANNED_PEERS_FILENAME);
    if let Ok(json) = serde_json::to_string_pretty(&entries) {
        if let Err(e) = std::fs::write(&path, json) {
            eprintln!("[p2p] ⚠ Konnte Ban-Liste nicht speichern: {e}");
        }
    }
}

/// NAT-Status des Nodes
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NatStatus {
    Unknown,
    Public,
    Private,
}

/// Prüft ob eine IPv6-Adresse nicht global routbar ist (Link-Local, ULA, etc.)
fn is_ipv6_non_global(ip: &std::net::Ipv6Addr) -> bool {
    let seg = ip.segments();
    // Link-Local: fe80::/10
    (seg[0] & 0xffc0) == 0xfe80
    // Unique Local (ULA): fc00::/7
    || (seg[0] & 0xfe00) == 0xfc00
    // Site-Local (deprecated): fec0::/10
    || (seg[0] & 0xffc0) == 0xfec0
}

/// Entfernt die `/p2p/<PeerId>`-Komponente am Ende einer Multiaddr.
/// mDNS liefert Adressen wie `/ip4/1.2.3.4/tcp/7654/p2p/12D3Koo…`.
/// libp2p lehnt es ab, wenn man diese an `DialOpts::peer_id(...).addresses(…)`
/// übergibt — die PeerId wäre dann doppelt vorhanden → EINVAL (os error 22).
fn strip_p2p_suffix(addr: libp2p::Multiaddr) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;
    let without: libp2p::Multiaddr = addr
        .into_iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect();
    without
}

impl SwarmTask {
    pub(crate) async fn run(mut self) {
        let listen_addr: Multiaddr = match self.config.listen_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                let _ = self.event_tx.send(NetworkEvent::Error {
                    message: format!("Ungültige Listen-Adresse: {e}"),
                });
                return;
            }
        };

        // Port-Fallback: falls konfigurierter Port belegt → zufälligen Port nehmen
        if let Err(e) = self.swarm.listen_on(listen_addr.clone()) {
            eprintln!("[p2p] ⚠️  Konnte {listen_addr} nicht binden: {e}");
            let fallback: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
            if let Err(e2) = self.swarm.listen_on(fallback) {
                let _ = self.event_tx.send(NetworkEvent::Error {
                    message: format!("Kein P2P-Port verfügbar: {e2}"),
                });
                return;
            }
            eprintln!("[p2p] ℹ️  Nutze zufälligen P2P-Port (STONE_P2P_PORT setzen um festen Port zu erzwingen)");
        }

        // ── QUIC-Transport: UDP-Listener auf dem gleichen Port ────────────────
        // QUIC hat bessere NAT-Traversal-Eigenschaften als TCP, da UDP Hole-
        // Punching zuverlässiger funktioniert. Wir lauschen auf beiden Protokollen.
        {
            // Port aus der TCP-Adresse extrahieren
            let tcp_port = listen_addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(port) = p {
                    Some(port)
                } else {
                    None
                }
            }).unwrap_or(DEFAULT_P2P_PORT);

            let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{tcp_port}/quic-v1")
                .parse()
                .unwrap();
            match self.swarm.listen_on(quic_addr.clone()) {
                Ok(_) => println!("[p2p] 🚀 QUIC-Transport aktiv auf UDP/{tcp_port}"),
                Err(e) => eprintln!("[p2p] ⚠️  QUIC konnte nicht gestartet werden: {e}"),
            }

            // Auch IPv6 QUIC wenn verfügbar
            let quic_v6: Multiaddr = format!("/ip6/::/udp/{tcp_port}/quic-v1")
                .parse()
                .unwrap();
            match self.swarm.listen_on(quic_v6) {
                Ok(_) => println!("[p2p] 🚀 QUIC-Transport aktiv auf UDP/{tcp_port} (IPv6)"),
                Err(e) => {
                    // IPv6 oft nicht verfügbar – nur Debug-Level
                    let _ = e; // kein Fehler-Log nötig
                }
            }
        }

        // Dual-Stack: Bei IPv4-Config zusätzlich IPv6 TCP versuchen (und umgekehrt)
        if self.config.listen_addr.starts_with("/ip6/") {
            // Port aus listen_addr extrahieren
            let port = listen_addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(port) = p {
                    Some(port)
                } else {
                    None
                }
            }).unwrap_or(4001);
            let ipv4_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap();
            match self.swarm.listen_on(ipv4_addr.clone()) {
                Ok(_) => println!("[p2p] Dual-Stack: lausche zusätzlich auf {ipv4_addr}"),
                Err(e) => eprintln!("[p2p] ⚠️  IPv4-Dual-Stack fehlgeschlagen: {e}"),
            }
        } else {
            // IPv4-Config → auch IPv6-TCP versuchen (Dual-Stack)
            let port = listen_addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(port) = p {
                    Some(port)
                } else {
                    None
                }
            }).unwrap_or(DEFAULT_P2P_PORT);
            let ipv6_addr: Multiaddr = format!("/ip6/::/tcp/{port}").parse().unwrap();
            match self.swarm.listen_on(ipv6_addr) {
                Ok(_) => println!("[p2p] Dual-Stack: lausche zusätzlich auf IPv6 TCP/{port}"),
                Err(_) => {} // IPv6 oft nicht verfügbar – kein Fehler
            }
        }

        // Bootstrap-Nodes einwählen
        for addr_str in self.bootstrap_addrs.clone() {
            self.dial_bootstrap(&addr_str);
        }

        if !self.bootstrap_addrs.is_empty() && self.config.kad_enabled {
            let _ = self.swarm.behaviour_mut().kad.bootstrap();
        }

        // Relay-Reservierungen herstellen (falls konfiguriert)
        if !self.relay_addrs.is_empty() {
            println!("[p2p] 📡 {} Relay-Node(s) konfiguriert – stelle Verbindungen her...", self.relay_addrs.len());
            self.establish_relay_reservations();
        }

        // Reconnect-Intervall (0 = deaktiviert)
        let reconnect_interval = if self.config.reconnect_interval_secs > 0 {
            Duration::from_secs(self.config.reconnect_interval_secs)
        } else {
            Duration::from_secs(u64::MAX / 2) // praktisch nie
        };

        let mut reconnect_ticker = tokio::time::interval(reconnect_interval);
        reconnect_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Periodischer Sync-Check: alle 30s prüfen ob verbundene Peers mehr Blöcke haben
        let mut sync_ticker = tokio::time::interval(Duration::from_secs(30));
        sync_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Sync-Buffer Flush-Ticker: alle 500ms prüfen ob gepufferte Blöcke geflusht werden können
        let mut flush_ticker = tokio::time::interval(Duration::from_millis(500));
        flush_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Cleanup-Ticker: alle 5 Minuten verwaiste rate_limiters, penalties, storage aufräumen
        let mut cleanup_ticker = tokio::time::interval(Duration::from_secs(300));
        cleanup_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Keepalive-Ticker: alle 45s Pings an verbundene Peers senden um NAT-Mappings warm zu halten
        let mut keepalive_ticker = tokio::time::interval(Duration::from_secs(45));
        keepalive_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = self.swarm.next() => {
                    match event {
                        Some(ev) => self.handle_swarm_event(ev).await,
                        None => break,
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => { if self.handle_command(c) { break; } }
                        None => break,
                    }
                }
                _ = reconnect_ticker.tick() => {
                    self.reconnect_bootstrap_nodes();
                }
                _ = sync_ticker.tick() => {
                    self.sync_with_connected_peers();
                }
                _ = flush_ticker.tick() => {
                    if !self.sync_buffer.is_empty() {
                        self.flush_sync_buffer();
                    }
                }
                _ = cleanup_ticker.tick() => {
                    self.periodic_cleanup();
                }
                _ = keepalive_ticker.tick() => {
                    self.keepalive_ping_peers();
                }
            }
        }
        println!("[p2p] Swarm-Task beendet.");
    }

    // ── Duplicate-Filter ─────────────────────────────────────────────────────

    /// Gibt true zurück wenn der Hash bereits gesehen wurde (Duplikat).
    fn is_duplicate(&mut self, hash: &str) -> bool {
        if self.seen_hashes.contains(hash) {
            return true;
        }
        // Neu: in Cache aufnehmen
        if self.seen_order.len() >= SEEN_CACHE_SIZE {
            // Ältesten Eintrag entfernen
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_hashes.remove(&oldest);
            }
        }
        self.seen_hashes.insert(hash.to_string());
        self.seen_order.push_back(hash.to_string());
        false
    }

    // ── Bootstrap / Reconnect ────────────────────────────────────────────────

    fn dial_bootstrap(&mut self, addr_str: &str) {
        // Placeholder-Adressen aus der Beispiel-Config überspringen
        if addr_str.contains("12D3KooW...") || addr_str.contains("1.2.3.4") {
            println!("[p2p] Bootstrap '{addr_str}' übersprungen (Placeholder) – bitte echte Adresse eintragen");
            return;
        }
        if addr_str.trim().is_empty() {
            return;
        }
        match addr_str.parse::<Multiaddr>() {
            Ok(addr) => {
                use libp2p::multiaddr::Protocol;
                let peer_id = addr.iter().find_map(|p| {
                    if let Protocol::P2p(pid) = p { Some(pid) } else { None }
                });
                if let Some(pid) = peer_id {
                    // Eigene PeerId nicht anwählen (Seed-Node wählt sich sonst selbst an)
                    if pid == *self.swarm.local_peer_id() {
                        return;
                    }
                    self.swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    println!("[p2p] Bootstrap-Node: {pid} @ {addr}");
                }
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    eprintln!("[p2p] Dial {addr} fehlgeschlagen: {e}");
                }
            }
            Err(e) => eprintln!("[p2p] Ungültige Bootstrap-Adresse '{addr_str}': {e}"),
        }
    }

    fn reconnect_bootstrap_nodes(&mut self) {
        let now = Instant::now();
        let connected_peer_ids: HashSet<String> = self.peers.values()
            .filter(|p| p.connected)
            .map(|p| p.peer_id.clone())
            .collect();

        // Wenn wir gar keine Verbindungen haben → alle Bootstrap-Nodes anwählen
        // (priorisiert: SEED_NODES stehen am Anfang der Liste = VPS zuerst)
        let no_connections = connected_peer_ids.is_empty();

        if !no_connections {
            // Prüfen ob alle bekannten Peers bereits verbunden sind
            let disconnected_count = self.peers.values()
                .filter(|p| !p.connected)
                .count();
            if disconnected_count == 0 && !self.peers.is_empty() {
                return; // alle bereits verbunden
            }
        }

        // Backoff für erfolgreich verbundene Peers zurücksetzen
        for pid in self.swarm.connected_peers().cloned().collect::<Vec<_>>() {
            self.reconnect_backoff.remove(&pid);
        }

        let mut attempted = 0u32;
        for addr_str in self.bootstrap_addrs.clone() {
            use libp2p::multiaddr::Protocol;
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                let peer_id_opt = addr.iter().find_map(|p| {
                    if let Protocol::P2p(pid) = p {
                        Some(pid)
                    } else {
                        None
                    }
                });
                if let Some(pid) = peer_id_opt {
                    // Eigene PeerId nicht anwählen
                    if pid == *self.swarm.local_peer_id() {
                        continue;
                    }
                    if connected_peer_ids.contains(&pid.to_string()) {
                        continue;
                    }

                    // ── Exponentieller Backoff pro Peer ──────────────────
                    // Verhindert Connect-Disconnect-Storm wenn beide Seiten
                    // gleichzeitig dialen und libp2p die doppelte Verbindung
                    // sofort wieder schließt.
                    const MIN_BACKOFF: Duration = Duration::from_secs(5);
                    const MAX_BACKOFF: Duration = Duration::from_secs(300); // 5 min

                    if let Some((next_try, _)) = self.reconnect_backoff.get(&pid) {
                        if now < *next_try {
                            continue; // Backoff noch nicht abgelaufen
                        }
                    }

                    // Backoff aktualisieren: verdoppeln (exponentiell), max 5 min
                    let current_backoff = self.reconnect_backoff
                        .get(&pid)
                        .map(|(_, d)| *d)
                        .unwrap_or(MIN_BACKOFF);
                    let next_backoff = (current_backoff * 2).min(MAX_BACKOFF);
                    self.reconnect_backoff.insert(
                        pid,
                        (now + next_backoff, next_backoff),
                    );

                    println!("[p2p] Reconnect-Versuch: {pid} ({addr_str}) [backoff={:.0}s]", next_backoff.as_secs_f64());
                    let _ = self.swarm.dial(addr);
                    attempted += 1;
                }
            }
        }

        if no_connections && attempted > 0 {
            // Bei null Verbindungen: auch Kademlia-Bootstrap anstoßen
            if self.config.kad_enabled {
                let _ = self.swarm.behaviour_mut().kad.bootstrap();
            }
            println!("[p2p] ⚠ Keine Verbindungen – {attempted} Bootstrap-Dial(s) gestartet");
        }

        self.last_reconnect = now;
    }

    // ── Swarm-Events ─────────────────────────────────────────────────────────

    async fn handle_swarm_event(&mut self, event: SwarmEvent<StoneBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, .. } => {
                // Gebannte Peers sofort trennen
                if self.is_peer_banned(&peer_id) {
                    eprintln!("[p2p] 🔨 Verbindung von gebantem Peer {peer_id} getrennt");
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                let addr = endpoint.get_remote_address().to_string();
                let now = chrono::Utc::now().timestamp();
                // Nur loggen wenn es die erste Verbindung zu diesem Peer ist
                if num_established.get() == 1 {
                    println!("[p2p] ✓ Verbunden: {peer_id} @ {addr}");
                }

                let entry = self.peers.entry(peer_id).or_insert_with(|| PeerInfo {
                    peer_id: peer_id.to_string(),
                    addresses: vec![addr.clone()],
                    agent_version: String::new(),
                    connected: false,
                    last_seen: now,
                    blocks_received: 0,
                    stake_level: 0,
                });
                entry.connected = true;
                entry.last_seen = now;
                if !entry.addresses.contains(&addr) {
                    entry.addresses.push(addr.clone());
                }

                // Events + Sync nur bei erster Verbindung
                if num_established.get() == 1 {
                    let _ = self.event_tx.send(NetworkEvent::PeerConnected {
                        peer_id: peer_id.to_string(),
                        addr,
                    });

                    // Chain-Sync anstoßen:
                    // 1) Direkte ChainInfo-Anfrage per Request/Response (sofort zuverlässig)
                    if self.config.auto_sync_on_connect {
                        let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                            &peer_id,
                            BlockRequest { block_index: BLOCK_REQUEST_CHAIN_INFO, block_index_end: None },
                        );
                        self.pending_chain_info.insert(req_id, peer_id);
                        println!("[p2p] 🔄 ChainInfo-Anfrage an {peer_id} gesendet (Initial-Sync)");
                    }
                    // 2) GossipSub-Handshake zusätzlich (für Peers die später joinen)
                    if self.config.auto_sync_on_connect {
                        self.send_sync_handshake();
                    }
                }
            }

            SwarmEvent::ConnectionClosed { peer_id, num_established, cause, .. } => {
                let reason = cause.map(|e| e.to_string()).unwrap_or_default();
                // Nur loggen wenn es die letzte Verbindung zu diesem Peer war
                if num_established == 0 {
                    println!("[p2p] ✗ Getrennt: {peer_id} ({reason})");

                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.connected = false;
                    }
                    let _ = self.event_tx.send(NetworkEvent::PeerDisconnected {
                        peer_id: peer_id.to_string(),
                    });
                }
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                let local_peer = *self.swarm.local_peer_id();
                let full_addr = format!("{address}/p2p/{local_peer}");
                println!("[p2p] 🎧 Lausche auf: {full_addr}");
                let _ = self.event_tx.send(NetworkEvent::Listening { addr: full_addr.clone() });

                // Relay-Circuit-Adressen als externe Adresse bekanntgeben,
                // damit Identify sie an andere Peers verbreitet.
                let is_circuit = address.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit));
                if is_circuit {
                    let ext_addr = address.clone()
                        .with(libp2p::multiaddr::Protocol::P2p(local_peer));
                    self.swarm.add_external_address(ext_addr.clone());
                    // Auch in Kademlia eintragen
                    self.swarm.behaviour_mut().kad.add_address(&local_peer, ext_addr.clone());
                    println!("[p2p] 🌍 Circuit-Listen als externe Adresse: {ext_addr}");
                }
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let local = *self.swarm.local_peer_id();
                // Selbst-Dial-Fehler (eigene VPN/Multi-Interface-Adressen) unterdrücken
                if peer_id == Some(local) {
                    return;
                }
                // Harmlose Race-Conditions komplett stumm schalten:
                // - "Already connected" / "Pending" → bereits verbunden, kein Problem
                // - os error 48 (EADDRINUSE, macOS) → TCP-Quelladresse kurz belegt, Peer
                //   verbindet sich gleichzeitig von der anderen Seite → ignorieren
                // - os error 22 (EINVAL) → /p2p/-Suffix im Dial-Addr, bereits gefixt aber
                //   kann noch aus alten Kademlia-Einträgen kommen → ignorieren
                let err_str = error.to_string();
                let is_harmless = err_str.contains("Already connected")
                    || err_str.contains("Pending connection")
                    || err_str.contains("WrongPeerId")
                    || err_str.contains("os error 48")   // EADDRINUSE (macOS)
                    || err_str.contains("os error 22")   // EINVAL
                    || err_str.contains("Address already in use")
                    || err_str.contains("Invalid argument");

                // Wenn der Peer jetzt bereits verbunden ist, war der Fehler eine Race-Condition
                let peer_now_connected = peer_id
                    .map(|id| self.swarm.is_connected(&id))
                    .unwrap_or(false);

                if is_harmless || peer_now_connected {
                    // Nur als Debug ausgeben, kein Fehler
                    return;
                }
                eprintln!("[p2p] Verbindungsfehler zu {:?}: {error}", peer_id);
            }

            SwarmEvent::Behaviour(bev) => self.handle_behaviour_event(bev),

            SwarmEvent::ExternalAddrConfirmed { address } => {
                println!("[p2p] 🌍 Externe Adresse bestätigt: {address}");
                // Adresse in Kademlia eintragen damit andere Nodes uns finden
                let local_peer = *self.swarm.local_peer_id();
                self.swarm.behaviour_mut().kad.add_address(
                    &local_peer,
                    address,
                );
            }

            _ => {}
        }
    }

    // ── Behaviour-Events ─────────────────────────────────────────────────────

    fn handle_behaviour_event(&mut self, event: StoneBehaviourEvent) {
        match event {
            // ── Identify ──────────────────────────────────────────────────────
            StoneBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                let addrs: Vec<String> = info.listen_addrs.iter().map(|a| a.to_string()).collect();
                println!("[p2p] Identify: {peer_id} – agent={}", info.agent_version);

                // SECURITY: Protokoll-Version prüfen. Peers mit inkompatibler
                // Major-Version werden getrennt um Chain-Korruption zu verhindern.
                {
                    let our_major = STONE_PROTOCOL_VERSION.split('/').nth(1)
                        .and_then(|v| v.split('.').next());
                    let peer_major = if info.agent_version.starts_with("stone/") {
                        info.agent_version.strip_prefix("stone/")
                            .and_then(|v| v.split('.').next())
                    } else {
                        None
                    };
                    if let (Some(ours), Some(theirs)) = (our_major, peer_major) {
                        if ours != theirs {
                            eprintln!(
                                "[p2p] ⚠ Peer {peer_id} hat inkompatible Version {} (wir: {}) – Verbindung getrennt",
                                info.agent_version, STONE_PROTOCOL_VERSION,
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
                    // - libp2p dedupliziert selbst (kein zweiter Dial wenn bereits pending)
                    // - strip_p2p_suffix: Kademlia braucht Adressen ohne /p2p-Suffix,
                    //   aber swarm.dial() braucht die vollständige Adresse MIT /p2p-Suffix
                    //   damit libp2p die PeerId verifizieren kann.
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

                if topic == TOPIC_BLOCKS {
                    self.handle_gossip_block(message.data, propagation_source);
                } else if topic == TOPIC_SYNC_HANDSHAKE {
                    self.handle_sync_handshake(message.data, propagation_source);
                } else if topic == TOPIC_MEMPOOL {
                    self.handle_gossip_tx(message.data, propagation_source);
                } else if topic == crate::updater::TOPIC_UPDATES {
                    println!("[p2p] 🆕 Update-Manifest von {propagation_source} empfangen");
                    let _ = self.event_tx.send(NetworkEvent::UpdateManifestReceived {
                        manifest_json: message.data,
                        from_peer: propagation_source.to_string(),
                    });
                } else if topic == TOPIC_STORAGE {
                    if let Ok(ann) = serde_json::from_slice::<StorageAnnouncement>(&message.data) {
                        println!(
                            "[p2p] 💾 Storage-Announcement von {} – {} GB angeboten, {} bytes belegt",
                            &ann.peer_id[..12.min(ann.peer_id.len())], ann.offered_gb, ann.used_bytes
                        );
                        self.peer_storage.insert(ann.peer_id.clone(), ann.clone());
                        let _ = self.event_tx.send(NetworkEvent::StorageAnnouncementReceived {
                            announcement: ann,
                            from_peer: propagation_source.to_string(),
                        });
                    }
                } else if topic == TOPIC_CHAT {
                    if let Ok(msg) = serde_json::from_slice::<crate::message_pool::PooledMessage>(&message.data) {
                        let _ = self.event_tx.send(NetworkEvent::ChatMessageReceived {
                            message: msg,
                            from_peer: propagation_source.to_string(),
                        });
                    }
                } else if topic == TOPIC_CHAT_CONTENT {
                    if let Ok(content) = serde_json::from_slice::<crate::chat::ChatContentSync>(&message.data) {
                        let _ = self.event_tx.send(NetworkEvent::ChatContentReceived {
                            content,
                            from_peer: propagation_source.to_string(),
                        });
                    }
                } else {
                    let _ = message_id; // acknowledged
                }
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
                        if *grace > RATE_LIMIT_GRACE {
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
                        // Chain-Info zurückgeben
                        let (height, genesis, latest) = if let Some(ref chain_arc) = self.chain_ref {
                            if let Ok(chain) = chain_arc.lock() {
                                let h = chain.blocks.len() as u64;
                                let g = chain.blocks.first().map(|b| b.hash.clone());
                                let l = chain.blocks.last().map(|b| b.hash.clone());
                                (Some(h), g, l)
                            } else {
                                (None, None, None)
                            }
                        } else {
                            (Some(self.local_chain_count), None, None)
                        };
                        println!("[p2p] 📊 ChainInfo-Anfrage von {peer} → height={height:?}");
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse {
                                block: None, blocks: vec![],
                                chain_height: height, genesis_hash: genesis, latest_hash: latest,
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
                        // Range-Response → IMMER als Batch via RangeSyncReceived senden
                        // (Einzelblock-Verarbeitung via sync_buffer führt zu PoA-Ablehnungen,
                        //  weil Range-Sync Blöcke keiner erneuten PoA-Prüfung bedürfen)
                        let block_count = response.blocks.len();
                        println!("[p2p] ← {block_count} Blöcke via Range-Sync von {peer}");

                        if let Some(entry) = self.peers.get_mut(&peer) {
                            entry.blocks_received += block_count as u64;
                        }
                        let _ = self.event_tx.send(NetworkEvent::RangeSyncReceived {
                            blocks: response.blocks,
                            from_peer: peer.to_string(),
                        });
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
                            let our_genesis = self.chain_ref.as_ref().and_then(|arc| {
                                arc.lock().ok().and_then(|c| c.blocks.first().map(|b| b.hash.clone()))
                            });
                            if let Some(ref our_gen) = our_genesis {
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

                        // Aktuelle lokale Höhe aus chain_ref lesen (genauer als local_chain_count)
                        let actual_local = self.chain_ref.as_ref()
                            .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
                            .unwrap_or(self.local_chain_count);

                        if remote_height > actual_local {
                            println!(
                                "[p2p] 🔄 Sync: Peer {peer} hat {remote_height} Blöcke, wir haben {actual_local} → hole {} fehlende",
                                remote_height - actual_local
                            );

                            // Bei kurzer lokaler Chain (< 50 Blöcke): von Block 1 starten
                            // um potentielle Forks aufzulösen (lokale Mining-Blöcke ersetzen)
                            let sync_from = if actual_local <= 50 { 1u64 } else { actual_local };

                            // Sync-Buffer NICHT leeren wenn bereits Blöcke drin sind
                            // (ein anderer Peer antwortet gleichzeitig → Blöcke behalten)
                            // Nur leeren wenn der Buffer Blöcke enthält die HINTER dem
                            // neuen Sync-Start liegen (= komplett veralteter Sync)
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
                        self.pending_chain_info.remove(&request_id);
                    }
                }
            },

            // Request-Fehler (Timeout, Verbindungsabbruch)
            StoneBehaviourEvent::BlockExchange(
                request_response::Event::OutboundFailure { peer, request_id, error, .. }
            ) => {
                if let Some((peer_id_str, _, reply)) = self.pending_pings.remove(&request_id) {
                    let _ = reply.send(PingResult {
                        peer_id: peer_id_str,
                        reachable: false,
                        latency_ms: None,
                        error: Some(error.to_string()),
                    });
                } else {
                    // pending_chain_info aufräumen bei Fehler (verhindert Memory-Leak + Sync-Blockade)
                    self.pending_chain_info.remove(&request_id);
                    eprintln!("[p2p] Request-Fehler zu {peer}: {error}");
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
                // Damit andere Peers (insbesondere NAT-Peers) uns über den Relay
                // finden können, muss die Circuit-Adresse via Identify verbreitet
                // und in Kademlia eingetragen werden.
                if let Some(info) = self.peers.get(&relay_peer_id) {
                    // Öffentliche Adresse des Relays finden
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
                                    // Event an den Event-Loop senden, damit die Registry aktualisiert wird
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
                if let Some((_chunk_hash, reply)) = self.pending_shard_lists.remove(&request_id) {
                    eprintln!("[p2p] Shard-Liste Fehler zu {peer}: {error}");
                    let _ = reply.send(vec![]);
                } else {
                    eprintln!("[p2p] Shard-Request Fehler zu {peer}: {error}");
                }
            }

            StoneBehaviourEvent::ShardExchange(_) => {}

            _ => {}
        }
    }

    // ── Relay-Reservierungen ───────────────────────────────────────────────

    /// Stellt Relay-Reservierungen bei allen konfigurierten Relay-Nodes her.
    /// Wird automatisch aufgerufen wenn AutoNAT „Private" meldet.
    fn establish_relay_reservations(&mut self) {
        let addrs: Vec<String> = self.relay_addrs.clone();
        for addr_str in &addrs {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    // Versuche die Relay-PeerId aus der Multiaddr zu extrahieren
                    let relay_peer_id = addr.iter().find_map(|p| {
                        if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                            Some(peer_id)
                        } else {
                            None
                        }
                    });

                    if let Some(relay_peer_id) = relay_peer_id {
                        // Eigene PeerId überspringen
                        if relay_peer_id == *self.swarm.local_peer_id() {
                            continue;
                        }
                        if self.active_relays.contains(&relay_peer_id) {
                            continue; // Bereits reserviert
                        }
                        println!("[p2p] 📡 Verbinde mit Relay {relay_peer_id}...");

                        // Dial den Relay-Node
                        if let Err(e) = self.swarm.dial(addr.clone()) {
                            eprintln!("[p2p] Relay-Dial fehlgeschlagen für {addr}: {e}");
                            continue;
                        }

                        // Lausche auf der Relay-Circuit-Adresse
                        let circuit_addr = addr.clone()
                            .with(libp2p::multiaddr::Protocol::P2pCircuit);
                        if let Err(e) = self.swarm.listen_on(circuit_addr.clone()) {
                            eprintln!("[p2p] Relay-Listen fehlgeschlagen: {e}");
                        } else {
                            println!("[p2p] 📡 Lausche via Relay-Circuit: {circuit_addr}");
                        }
                    } else {
                        eprintln!("[p2p] ⚠ Relay-Adresse hat keine PeerId: {addr_str}");
                    }
                }
                Err(e) => {
                    eprintln!("[p2p] Ungültige Relay-Adresse '{addr_str}': {e}");
                }
            }
        }
    }

    /// Auto-Discovery: Versucht alle verbundenen Peers als Relay zu nutzen.
    ///
    /// Wird aufgerufen wenn AutoNAT „Private" erkennt. Anstatt nur auf
    /// konfigurierte Relay-Nodes zu warten, probiert Stone jeden verbundenen
    /// Peer als Relay — da jeder Stone-Node gleichzeitig Relay-Server ist.
    /// Das ermöglicht NAT-Traversal ohne manuelle Konfiguration.
    fn auto_discover_relays(&mut self) {
        let local = *self.swarm.local_peer_id();
        let max_relay_attempts = 3; // Maximal 3 Relays gleichzeitig versuchen
        let mut attempts = 0;

        // Alle aktuell verbundenen Peers als potentielle Relays sammeln
        let connected_peers: Vec<(PeerId, Vec<Multiaddr>)> = self
            .peers
            .iter()
            .filter(|(pid, info)| {
                info.connected
                    && **pid != local
                    && !self.active_relays.contains(pid)
            })
            .map(|(pid, info)| {
                let addrs: Vec<Multiaddr> = info
                    .addresses
                    .iter()
                    .filter_map(|a| a.parse().ok())
                    .collect();
                (*pid, addrs)
            })
            .collect();

        for (peer_id, addrs) in connected_peers {
            if attempts >= max_relay_attempts {
                break;
            }

            // Bevorzuge öffentliche IP-Adressen (nicht 10.x, 192.168.x, etc.)
            let public_addr = addrs.iter().find(|a| {
                a.iter().any(|p| {
                    matches!(p,
                        libp2p::multiaddr::Protocol::Ip4(ip) if !ip.is_private() && !ip.is_loopback()
                    ) || matches!(p, libp2p::multiaddr::Protocol::Ip6(ip) if !ip.is_loopback() && !is_ipv6_non_global(&ip))
                })
            });

            // Fallback: nehme erste verfügbare Adresse
            let relay_base_addr = public_addr.or(addrs.first());

            if let Some(base_addr) = relay_base_addr {
                // Relay-Circuit-Adresse aufbauen: /ip4/.../tcp/.../p2p/<relayPeerId>/p2p-circuit
                // Erst vorhandenes /p2p/ entfernen um Duplikate zu vermeiden
                let stripped = strip_p2p_suffix(base_addr.clone());
                let circuit_addr = stripped
                    .with(libp2p::multiaddr::Protocol::P2p(peer_id))
                    .with(libp2p::multiaddr::Protocol::P2pCircuit);

                match self.swarm.listen_on(circuit_addr.clone()) {
                    Ok(_) => {
                        println!(
                            "[p2p] 🔍 Auto-Relay: Versuche {peer_id} als Relay ({circuit_addr})"
                        );
                        attempts += 1;
                    }
                    Err(e) => {
                        // Kein Fehler-Log: Viele Peers unterstützen es nicht → erwartbar
                        let _ = e;
                    }
                }
            }
        }

        if attempts > 0 {
            println!(
                "[p2p] 🔍 Auto-Relay: {} verbundene Peers als Relay-Kandidaten probiert",
                attempts
            );
        }
    }

    // ── Keepalive: Warm Peer Table ──────────────────────────────────────────

    /// Maximale Latenz-Samples pro Peer (Rolling Window)
    const LATENCY_WINDOW: usize = 10;

    /// Sendet Keepalive-Pings an alle verbundenen Peers um NAT-Mappings warm
    /// zu halten und Latenz-Statistiken zu sammeln.
    fn keepalive_ping_peers(&mut self) {
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
    fn handle_keepalive_response(&mut self, request_id: &request_response::OutboundRequestId) -> bool {
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

    /// Durchschnittliche Latenz eines Peers (aus Rolling-Window), oder None.
    fn avg_latency_ms(&self, peer_id: &PeerId) -> Option<u64> {
        let window = self.peer_latencies.get(peer_id)?;
        if window.is_empty() {
            return None;
        }
        let sum: u64 = window.iter().sum();
        Some(sum / window.len() as u64)
    }

    // ── Periodisches Aufräumen ────────────────────────────────────────────────

    /// Räumt verwaiste Einträge in Rate-Limitern, Penalty-Map und Storage-Announcements auf.
    /// Wird alle 5 Minuten vom Cleanup-Ticker aufgerufen.
    fn periodic_cleanup(&mut self) {
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
        let stale_pings: Vec<request_response::OutboundRequestId> = self.pending_pings.iter()
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

        // 6. Pending-Shard-Lists: verwaiste Einträge für nicht-verbundene Peers aufräumen
        {
            let before = self.pending_shard_lists.len();
            self.pending_shard_lists.retain(|_, (_, _reply)| {
                // oneshot::Sender::is_closed() prüfen: wenn Receiver gedroppt → aufräumen
                // Da wir keinen Timestamp haben, entfernen wir Einträge deren Receiver weg ist.
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

    // ── Peer-Scoring & Banning ────────────────────────────────────────────────

    /// Fügt einem Peer Penalty-Punkte hinzu. Bei Überschreitung des Schwellwerts
    /// wird der Peer gebannt (Verbindung getrennt).
    fn add_peer_penalty(&mut self, peer: &PeerId, points: u32, reason: &str) {
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
    fn is_peer_banned(&self, peer: &PeerId) -> bool {
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

    // ── Gossip Block verarbeiten ──────────────────────────────────────────────

    fn handle_gossip_block(&mut self, data: Vec<u8>, source: PeerId) {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return;
        }

        // ── Rate-Limit: Gossip-Blocks ─────────────────────────────────────────
        let limiter = self.peer_rate_limiters
            .entry(source)
            .or_insert_with(PeerRateLimiter::new);
        if !limiter.gossip_blocks.try_consume() {
            eprintln!("[p2p] ⚠ Rate-Limit für Gossip-Blocks von {source} erreicht – ignoriert");
            self.add_peer_penalty(&source, 15, "gossip block rate limit");
            return;
        }

        // ── Größenlimit: Blöcke > 10 MiB sind verdächtig ──────────────────────
        const MAX_GOSSIP_BLOCK_BYTES: usize = 10 * 1024 * 1024;
        if data.len() > MAX_GOSSIP_BLOCK_BYTES {
            eprintln!(
                "[p2p] ⚠ Block von {source} zu groß ({} Bytes) – ignoriert + Penalty",
                data.len()
            );
            self.add_peer_penalty(&source, 50, "oversized block");
            return;
        }

        match serde_json::from_slice::<Block>(&data) {
            Ok(block) => {
                // ── Duplicate-Filter ──────────────────────────────────────────
                if self.is_duplicate(&block.hash) {
                    return;
                }

                // ── Hash-Integrität ───────────────────────────────────────────
                let expected_hash = crate::blockchain::calculate_hash(&block);
                if expected_hash != block.hash {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Hash – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid hash");
                    return;
                }

                // ── Merkle-Root-Verifikation ──────────────────────────────────
                let expected_merkle = crate::blockchain::compute_merkle_root(
                    &block.documents,
                    &block.tombstones,
                    &block.transactions,
                );
                if expected_merkle != block.merkle_root {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Merkle-Root – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid merkle root");
                    return;
                }

                // ── Timestamp-Drift-Check ─────────────────────────────────────
                // Block-Timestamp darf nicht > 5 Minuten in der Zukunft liegen
                // und nicht > 24 Stunden in der Vergangenheit (außer Genesis)
                let now = chrono::Utc::now().timestamp();
                let max_future = 5 * 60;       // 5 Minuten Toleranz
                let max_past = 24 * 60 * 60;   // 24 Stunden
                if block.index > 0 {
                    if block.timestamp > now + max_future {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} liegt {} Sek. in der Zukunft – ignoriert",
                            block.index,
                            block.timestamp - now,
                        );
                        self.add_peer_penalty(&source, 30, "future timestamp");
                        return;
                    }
                    if block.timestamp < now - max_past {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} ist {} Stunden alt – ignoriert",
                            block.index,
                            (now - block.timestamp) / 3600,
                        );
                        self.add_peer_penalty(&source, 10, "stale timestamp");
                        return;
                    }
                }

                // ── Signer darf nicht leer sein ───────────────────────────────
                if block.signer.is_empty() && block.index > 0 {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat keinen Signer – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 50, "missing signer");
                    return;
                }

                // ── Ed25519-Validator-Signatur prüfen ─────────────────────────
                if block.index > 0 {
                    if block.validator_pub_key.is_empty() || block.validator_signature.is_empty() {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} hat keine Validator-Signatur – ignoriert",
                            block.index
                        );
                        self.add_peer_penalty(&source, 100, "missing validator signature");
                        return;
                    }
                    if !verify_block_signature_standalone(
                        &block.hash,
                        &block.validator_pub_key,
                        &block.validator_signature,
                    ) {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} hat ungültige Validator-Signatur – ignoriert",
                            block.index
                        );
                        self.add_peer_penalty(&source, 200, "invalid validator signature");
                        return;
                    }
                }

                // ── Block-Größe vs. data_size Plausibilität ───────────────────
                let actual_data_size: u64 = block.documents.iter().map(|d| d.size).sum();
                if block.data_size > 0 && actual_data_size == 0 && !block.documents.is_empty() {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source}: data_size Mismatch – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 30, "data_size mismatch");
                    return;
                }

                // ── Argon2id-PoW Schnellprüfung ──────────────────────────────
                // Blöcke ab dem Activation-Block müssen einen gültigen Argon2id-PoW haben.
                // Prüfung hier verhindert Weiterleitung ungültiger PoW-Blöcke im Gossip.
                {
                    use crate::consensus::{
                        ARGON2_POW_ACTIVATION_BLOCK, MIN_EFFECTIVE_POW_DIFFICULTY,
                        MAX_STAKE_DIFFICULTY_BONUS,
                    };
                    if block.index >= ARGON2_POW_ACTIVATION_BLOCK && block.index > 0 {
                        if block.pow_hash.is_empty() || block.pow_difficulty == 0 {
                            eprintln!(
                                "[p2p] ⚠ Block #{} von {source}: Argon2id-PoW fehlt – ignoriert",
                                block.index
                            );
                            self.add_peer_penalty(&source, 100, "missing pow");
                            return;
                        }
                        // PoS/PoW Hybrid: effective_difficulty Plausibilität prüfen
                        if block.effective_difficulty > 0 {
                            if block.effective_difficulty > block.pow_difficulty {
                                eprintln!(
                                    "[p2p] ⚠ Block #{} von {source}: effective_difficulty ({}) > pow_difficulty ({}) – ignoriert",
                                    block.index, block.effective_difficulty, block.pow_difficulty,
                                );
                                self.add_peer_penalty(&source, 100, "invalid effective_difficulty");
                                return;
                            }
                            if block.effective_difficulty < MIN_EFFECTIVE_POW_DIFFICULTY {
                                eprintln!(
                                    "[p2p] ⚠ Block #{} von {source}: effective_difficulty ({}) < MIN ({}) – ignoriert",
                                    block.index, block.effective_difficulty, MIN_EFFECTIVE_POW_DIFFICULTY,
                                );
                                self.add_peer_penalty(&source, 100, "effective_difficulty below min");
                                return;
                            }
                            let bonus = block.pow_difficulty - block.effective_difficulty;
                            if bonus > MAX_STAKE_DIFFICULTY_BONUS {
                                eprintln!(
                                    "[p2p] ⚠ Block #{} von {source}: Stake-Bonus ({}) > MAX ({}) – ignoriert",
                                    block.index, bonus, MAX_STAKE_DIFFICULTY_BONUS,
                                );
                                self.add_peer_penalty(&source, 100, "stake bonus too high");
                                return;
                            }
                        }
                        // PoW gegen effektive Difficulty verifizieren
                        let verify_difficulty = if block.effective_difficulty > 0 {
                            block.effective_difficulty
                        } else {
                            block.pow_difficulty
                        };
                        if !crate::consensus::verify_argon2_pow(
                            &block.previous_hash,
                            block.index,
                            &block.validator_pub_key,
                            block.pow_nonce,
                            &block.pow_hash,
                            verify_difficulty,
                        ) {
                            eprintln!(
                                "[p2p] ⚠ Block #{} von {source}: Ungültiger Argon2id-PoW (d={}) – ignoriert",
                                block.index, verify_difficulty,
                            );
                            self.add_peer_penalty(&source, 200, "invalid argon2id pow");
                            return;
                        }
                        // Stake-Verifizierung: effective_difficulty korrekt für den Miner?
                        // Detaillierte Prüfung erfolgt in accept_peer_block; hier nur Bounds-Check.
                    }
                }

                println!(
                    "[p2p] 📦 Block #{} von {source} (hash={}…, d={}/{}, cd={}) ✓ validiert",
                    block.index, &block.hash[..8],
                    block.effective_difficulty, block.pow_difficulty,
                    block.cumulative_difficulty,
                );

                if let Some(entry) = self.peers.get_mut(&source) {
                    entry.blocks_received += 1;
                    entry.last_seen = chrono::Utc::now().timestamp();
                }
                self.net_metrics.blocks_received += 1;

                // Aktuelle Chain-Höhe lesen um zu entscheiden ob gebuffert werden muss
                let actual_local = self.chain_ref.as_ref()
                    .and_then(|arc| arc.lock().ok().map(|c| c.blocks.len() as u64))
                    .unwrap_or(self.local_chain_count);

                if block.index < actual_local {
                    // ── Fork-Erkennung: Competing Block innerhalb Reorg-Tiefe ──
                    // Statt veraltet wegwerfen → als potenziellen Fork weiterleiten.
                    let depth = actual_local - block.index;
                    if depth <= crate::blockchain::MAX_REORG_DEPTH {
                        println!(
                            "[p2p] 🔀 Competing Block #{} von {source} (Tiefe: {depth}) – weiterleiten",
                            block.index,
                        );
                        let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                            block: Box::new(block),
                            from_peer: source.to_string(),
                        });
                    }
                    // Blöcke jenseits MAX_REORG_DEPTH → wirklich veraltet
                    return;
                }

                // Block ist voraus ODER Sync-Buffer ist aktiv → puffern
                // Dies fängt auch Gossip-Blöcke die VOR dem Sync-Start ankommen!
                if block.index > actual_local || !self.sync_buffer.is_empty() {
                    self.sync_buffer.insert(block.index, (block, source.to_string()));
                    self.sync_buffer_last_insert = Some(Instant::now());
                    self.flush_sync_buffer();
                } else {
                    // Normalfall: Block ist der nächste erwartete und kein Sync aktiv
                    let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                        block: Box::new(block),
                        from_peer: source.to_string(),
                    });
                }
            }
            Err(e) => {
                eprintln!("[p2p] Gossip Block-Dekodierung fehlgeschlagen von {source}: {e}");
                self.add_peer_penalty(&source, 20, "malformed block");
            }
        }
    }

    // ── Gossipsub: Token-TX empfangen ─────────────────────────────────────────

    fn handle_gossip_tx(&mut self, data: Vec<u8>, source: PeerId) {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return;
        }

        // ── Rate-Limit: Gossip-TXs ────────────────────────────────────────────
        let limiter = self.peer_rate_limiters
            .entry(source)
            .or_insert_with(PeerRateLimiter::new);
        if !limiter.gossip_txs.try_consume() {
            eprintln!("[p2p] ⚠ Rate-Limit für Gossip-TXs von {source} erreicht – ignoriert");
            self.add_peer_penalty(&source, 10, "gossip tx rate limit");
            return;
        }

        // Größenlimit: TXs > 64 KiB sind verdächtig
        const MAX_TX_BYTES: usize = 64 * 1024;
        if data.len() > MAX_TX_BYTES {
            eprintln!(
                "[p2p] ⚠ TX von {source} zu groß ({} Bytes) – ignoriert",
                data.len()
            );
            self.add_peer_penalty(&source, 20, "oversized tx");
            return;
        }

        match serde_json::from_slice::<crate::token::TokenTx>(&data) {
            Ok(tx) => {
                // Stake/Unstake-TXs dürfen nur lokal über authentifizierte
                // API-Handler erstellt werden – via P2P ablehnen.
                if tx.tx_type == crate::token::TxType::Stake
                    || tx.tx_type == crate::token::TxType::Unstake
                {
                    eprintln!(
                        "[p2p] ⚠ {:?}-TX {} von {source} via Gossip abgelehnt (nur lokal erlaubt)",
                        tx.tx_type, &tx.tx_id[..12.min(tx.tx_id.len())]
                    );
                    self.add_peer_penalty(&source, 50, "unauthorized stake/unstake via gossip");
                    return;
                }

                // Duplikat-Filter (tx_id basiert)
                let key = format!("tx:{}", tx.tx_id);
                if self.is_duplicate(&key) {
                    return;
                }

                // Signatur prüfen
                if let Err(e) = crate::token::validate_tx(&tx) {
                    eprintln!(
                        "[p2p] ⚠ TX {} von {source} ungültige Signatur: {e} – ignoriert",
                        tx.tx_id
                    );
                    self.add_peer_penalty(&source, 30, "invalid tx signature");
                    return;
                }

                println!("[p2p] 💸 TX {} von {source} empfangen", &tx.tx_id[..12.min(tx.tx_id.len())]);

                self.net_metrics.txs_received += 1;

                let _ = self.event_tx.send(NetworkEvent::TxReceived {
                    tx: Box::new(tx),
                    from_peer: source.to_string(),
                });
            }
            Err(e) => {
                eprintln!("[p2p] Gossip TX-Dekodierung fehlgeschlagen von {source}: {e}");
                self.add_peer_penalty(&source, 10, "malformed tx");
            }
        }
    }

    // ── Chain-Sync Handshake ──────────────────────────────────────────────────

    /// Flusht geordnete Blöcke aus dem Sync-Buffer in den Event-Channel.
    /// Nur zusammenhängende Blöcke ab `sync_expected_next` werden gesendet.
    fn flush_sync_buffer(&mut self) {
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
            // NICHT local_chain_count hier setzen – master_server aktualisiert
            // es über SetLocalChainCount wenn Blöcke tatsächlich akzeptiert werden
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
    fn sync_with_connected_peers(&mut self) {
        // ── local_chain_count aus chain_ref aktualisieren ──────────────
        // Damit der Wert auch nach lokal geminteten Blöcken stimmt.
        if let Some(arc) = &self.chain_ref {
            if let Ok(chain) = arc.lock() {
                self.local_chain_count = chain.blocks.len() as u64;
            }
        }

        // ── Verwaiste pending_chain_info aufräumen ─────────────────────
        // Einträge für nicht mehr verbundene Peers oder solche die > 30s alt sind
        // entfernen, damit neue Sync-Anfragen möglich sind.
        {
            let connected_ids: HashSet<PeerId> = self.peers.iter()
                .filter(|(_, info)| info.connected)
                .map(|(pid, _)| *pid)
                .collect();
            self.pending_chain_info.retain(|_, peer_id| connected_ids.contains(peer_id));
        }

        // Verbundene Peers nach Stake-Level sortieren (höchster Stake zuerst).
        // Bei Chain-Sync werden damit höher-gestakte Peers bevorzugt angefragt.
        let mut connected: Vec<(PeerId, u64)> = self.peers.iter()
            .filter(|(_, info)| info.connected)
            .map(|(pid, info)| (*pid, info.stake_level))
            .collect();
        connected.sort_by(|a, b| b.1.cmp(&a.1));

        if connected.is_empty() {
            return;
        }

        // local_chain_count ist jetzt aktuell (oben refreshed)

        // Nur syncen wenn wir möglicherweise hinterher sind
        // (auch GossipSub-Handshake senden für Peers die hinter UNS sind)
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
    fn send_sync_handshake(&mut self) {
        // Genesis-Hash aus chain_ref lesen
        let genesis_hash = self.chain_ref.as_ref().and_then(|arc| {
            arc.lock().ok().and_then(|c| c.blocks.first().map(|b| b.hash.clone()))
        });
        // Aktuelle Höhe aus chain_ref (local_chain_count wird in sync_with_connected_peers aktualisiert)
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
    fn handle_sync_handshake(&mut self, data: Vec<u8>, source: PeerId) {
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
            // Major-Version vergleichen (z.B. "stone/0.7" vs "stone/0.7")
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

            // Sync-Buffer NICHT leeren wenn bereits Blöcke drin sind (parallele Syncs)
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

            // Bei kurzer lokaler Chain: von Block 1 starten (Fork-Auflösung)
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

    // ── Externe Befehle ───────────────────────────────────────────────────────

    fn handle_command(&mut self, cmd: NetworkCommand) -> bool {
        match cmd {
            NetworkCommand::BroadcastBlock(block) => {
                let hash = block.hash.clone();

                // Eigenen Block sofort als "gesehen" markieren (kein Re-Broadcast)
                if !self.is_duplicate(&hash) {
                    // Duplicate-Filter hat ihn gerade neu eingetragen → gut
                }

                match serde_json::to_vec(&*block) {
                    Ok(data) => {
                        let data_len = data.len() as u64;
                        let topic = IdentTopic::new(TOPIC_BLOCKS);
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

                match serde_json::to_vec(&*tx) {
                    Ok(data) => {
                        let data_len = data.len() as u64;
                        let topic = IdentTopic::new(TOPIC_MEMPOOL);
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
                let _ = our_block_count; // wird für Logging genutzt falls nötig
                false
            }

            NetworkCommand::SetLocalChainCount(count) => {
                self.local_chain_count = count;
                false
            }

            NetworkCommand::SetChainRef(chain_arc) => {
                println!("[p2p] Chain-Referenz gesetzt");
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
                    .mesh_peers(&gossipsub::TopicHash::from_raw(TOPIC_BLOCKS))
                    .map(|p| p.to_string())
                    .collect();

                // Direkt aus dem Swarm die verbundenen Peers holen —
                // das ist die einzig zuverlässige Quelle, unabhängig von peers-Map.
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

                let connected = swarm_connected.len(); // direkt aus Swarm

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
                });
                false
            }

            NetworkCommand::Shutdown => {
                println!("[p2p] Shutdown.");
                true
            }

            // ── Shard-Befehle ─────────────────────────────────────────────────

            NetworkCommand::RequestShard { peer_id, chunk_hash, shard_index } => {
                println!("[p2p] → Shard anfordern: {chunk_hash}[{shard_index}] von {peer_id}");
                self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::GetShard { chunk_hash, shard_index },
                );
                false
            }

            NetworkCommand::StoreShard { peer_id, chunk_hash, shard_index, shard_hash, data } => {
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

// ─── Sync-Handshake Nachricht ─────────────────────────────────────────────────

pub const TOPIC_SYNC_HANDSHAKE: &str = "stone/sync/v1";

/// Kurze Nachricht die beim Verbinden gesendet wird um Chain-Längen zu vergleichen.
/// Enthält Genesis-Hash und Protokoll-Version für Kompatibilitätsprüfung.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncHandshake {
    block_count: u64,
    peer_id: String,
    /// Genesis-Block-Hash – Peers auf einer anderen Chain werden abgelehnt
    #[serde(default)]
    genesis_hash: Option<String>,
    /// Protokoll-Version (z.B. "stone/0.7") – inkompatible Versionen werden abgelehnt
    #[serde(default)]
    protocol_version: Option<String>,
    /// Stake-Level dieses Nodes (0/100/250/500) – höhere Stake = bevorzugter Sync-Partner
    #[serde(default)]
    stake_level: u64,
}

// ─── Gossipsub: Topics abonnieren ─────────────────────────────────────────────

pub(crate) fn subscribe_all_topics(gossipsub: &mut gossipsub::Behaviour) -> Result<(), String> {
    for topic in [TOPIC_BLOCKS, TOPIC_PEERS, TOPIC_SYNC_HANDSHAKE, TOPIC_MEMPOOL, TOPIC_CHAT, TOPIC_CHAT_CONTENT, crate::updater::TOPIC_UPDATES, TOPIC_STORAGE] {
        gossipsub.subscribe(&IdentTopic::new(topic))
            .map_err(|e| format!("Subscribe '{topic}': {e}"))?;
    }
    Ok(())
}
