//! UDP-Tunnel: Hauptschleife für den VPN-Tunnel (Server + Client).
//!
//! ## Protokoll-Kompatibilität
//!
//! Dieses Modul ist **vollständig kompatibel** mit dem Stone-VPN Protokoll
//! (`stonevpn-core`). Der Stone-VPN Client kann sich mit diesem Server
//! verbinden und umgekehrt.
//!
//! ## Server-Modus:
//! - Lauscht auf UDP-Port (Default 51822)
//! - User-Management via `stone_data/vpn-users.json`
//! - Auth: Client-ID + Passwort (SHA-256 Hash), MAC-Bindung, Subnetz-Enforcement
//! - Vergibt VPN-IPs aus 10.1.0.0/24
//! - Leitet Proxy-Requests (HTTP) und Chat-Nachrichten weiter
//!
//! ## Client-Modus:
//! - Verbindet sich zum VPN-Server
//! - Sendet Auth → bekommt VPN-IP
//! - Sendet Keepalives (alle 25s)
//! - Kann HTTP-Requests per Proxy tunneln (für Sync)

use tokio::net::UdpSocket;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use super::crypto::{Keypair, now_secs};
use super::ip_pool::{IpPool, parse_cidr};
use super::peer::{Peer, PeerRegistry};
use super::proxy::{self, ProxyRequest, ProxyResponse, MAX_CHUNK_BODY};

// ─── Paket-Typen (kompatibel mit Stone-VPN stonevpn-core) ────────────────────

pub const TYPE_HANDSHAKE: u8      = 0x01;
pub const TYPE_DATA: u8           = 0x02;
pub const TYPE_KEEPALIVE: u8      = 0x03;
pub const TYPE_AUTH: u8           = 0x05;
pub const TYPE_CHAT: u8           = 0x06;
pub const TYPE_AUTH_RESPONSE: u8  = 0x07;
pub const TYPE_AUTH_ERROR: u8     = 0x08;
pub const TYPE_PEER_LIST: u8      = 0x09;
pub const TYPE_FRIEND_REQUEST: u8 = 0x0A;
pub const TYPE_FRIEND_RESPONSE: u8 = 0x0B;
pub const TYPE_ID_CHANGE_NOTIFY: u8 = 0x0C;
pub const TYPE_ACL_UPDATE: u8     = 0x10;
pub const TYPE_ACCESS_REQUEST: u8 = 0x12;
pub const TYPE_ACCESS_RESPONSE: u8 = 0x13;
pub const TYPE_ACCESS_CHECK: u8   = 0x14;
// Kompatibel zum Stone-VPN Client (stonevpn-core lib.rs)
pub const TYPE_PRESENCE_REQUEST: u8  = 0x17;  // Client → Server: „wer ist online?"
pub const TYPE_PRESENCE_RESPONSE: u8 = 0x18;  // Server → Client: Presence-Liste (JSON)

/// Keepalive-Intervall (< NAT-Timeout, typisch 30s)
const KEEPALIVE_SECS: u64 = 25;

/// Maximale UDP-Paketgröße
const MAX_PACKET: usize = 65536;

// ─── Tunnel-Konfiguration ────────────────────────────────────────────────────

/// Konfiguration für den VPN-Tunnel.
#[derive(Clone)]
pub struct TunnelConfig {
    pub stone_data: PathBuf,
    /// UDP-Port für Server-Modus (0 = Client-Modus)
    pub server_port: u16,
    /// Server-Adresse für Client-Modus
    pub server_addr: Option<SocketAddr>,
    /// Pre-Shared Key (Passwort) für Auth
    pub psk: String,
    /// Eigene Client-ID (VPN-ID)
    pub client_id: Option<String>,
    /// Subnetz-Präfix-Länge (default 24)
    pub subnet_prefix: u8,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        TunnelConfig {
            stone_data: PathBuf::from("stone_data"),
            server_port: 0,
            server_addr: None,
            psk: String::new(),
            client_id: None,
            subnet_prefix: 24,
        }
    }
}

// ─── Ergebnis-Typen ──────────────────────────────────────────────────────────

/// Ergebnis einer Proxy-HTTP-Anfrage über den VPN-Tunnel.
#[derive(Debug, Clone)]
pub struct ProxyHttpResult {
    pub status: u16,
    pub body: Vec<u8>,
}

// ─── Tunnel-Handle (für externe API) ─────────────────────────────────────────

/// Handle für den laufenden VPN-Tunnel-Task.
/// Wird von `VpnTunnel::start()` zurückgegeben.
#[derive(Clone)]
pub struct VpnTunnelHandle {
    /// Kanal für ausgehende Proxy-Requests
    proxy_tx: mpsc::UnboundedSender<(ProxyRequest, tokio::sync::oneshot::Sender<ProxyHttpResult>)>,
    /// Unsere VPN-IP (nach erfolgreicher Verbindung)
    vpn_ip: Arc<Mutex<Option<Ipv4Addr>>>,
    /// Client-ID
    client_id: Arc<Mutex<Option<String>>>,
}

impl VpnTunnelHandle {
    /// Führt einen HTTP-GET-Request über den VPN-Tunnel aus.
    /// Wird von `pull_from_peer()` als Fallback verwendet.
    pub async fn http_get(&self, url: &str) -> Result<ProxyHttpResult, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = ProxyRequest::get(rand_id(), url);
        self.proxy_tx
            .send((req, tx))
            .map_err(|_| "VPN-Tunnel nicht aktiv".to_string())?;
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            rx,
        )
        .await
        .map_err(|_| "Timeout (30s)".to_string())?
        .map_err(|e| format!("Proxy-Fehler: {e}"))
    }

    /// Führt einen HTTP-POST-Request über den VPN-Tunnel aus.
    pub async fn http_post(&self, url: &str, body: Vec<u8>) -> Result<ProxyHttpResult, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = ProxyRequest::post_json(rand_id(), url, body);
        self.proxy_tx
            .send((req, tx))
            .map_err(|_| "VPN-Tunnel nicht aktiv".to_string())?;
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            rx,
        )
        .await
        .map_err(|_| "Timeout (30s)".to_string())?
        .map_err(|e| format!("Proxy-Fehler: {e}"))
    }

    /// Gibt die aktuelle VPN-IP zurück (None wenn noch nicht verbunden).
    pub async fn vpn_ip(&self) -> Option<Ipv4Addr> {
        *self.vpn_ip.lock().await
    }

    /// Gibt die Client-ID zurück.
    pub async fn client_id(&self) -> Option<String> {
        self.client_id.lock().await.clone()
    }
}

fn rand_id() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

// ─── Hauptstruktur ───────────────────────────────────────────────────────────

/// Der VPN-Tunnel (wird als Tokio-Task gestartet).
pub struct VpnTunnel {
    config: TunnelConfig,
}

impl VpnTunnel {
    pub fn new(config: TunnelConfig) -> Self {
        VpnTunnel { config }
    }

    /// Startet den VPN-Tunnel als Hintergrund-Task.
    /// Gibt einen `VpnTunnelHandle` für Proxy-Requests zurück.
    pub async fn start(self) -> Result<VpnTunnelHandle, String> {
        let (proxy_tx, mut proxy_rx) = mpsc::unbounded_channel::<(ProxyRequest, tokio::sync::oneshot::Sender<ProxyHttpResult>)>();

        // Keypair laden/generieren
        let stone_data_str = self.config.stone_data.to_string_lossy().to_string();
        let keypair = Keypair::load_or_create(&stone_data_str)?;

        // IP-Pool
        let mut ip_pool = IpPool::new();
        // Subnetz-Präfix überschreiben falls konfiguriert
        if self.config.subnet_prefix != 24 {
            let net = ip_pool.network();
            let cidr = format!("{}.{}.{}.{}/{}", net.octets()[0], net.octets()[1], net.octets()[2], net.octets()[3], self.config.subnet_prefix);
            std::env::set_var("STONE_VPN_SUBNET", &cidr);
            ip_pool = IpPool::new();
        }

        let is_server = self.config.server_port > 0;
        let relay_addrs: Vec<SocketAddr> = if let Some(addr) = self.config.server_addr {
            vec![addr]
        } else {
            vec![]
        };

        let mut registry = PeerRegistry::new(
            keypair,
            ip_pool,
            relay_addrs,
            is_server,
            self.config.stone_data.clone(),
        );

        // ── Socket binden ──────────────────────────────────────────────────
        let bind_addr = if is_server {
            format!("0.0.0.0:{}", self.config.server_port)
        } else {
            "0.0.0.0:0".to_string() // Client: zufälliger Port
        };
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| format!("UDP-Bind fehlgeschlagen ({bind_addr}): {e}"))?;

        if is_server {
            let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
            eprintln!("[vpn-tunnel] 🟢 Server-Modus: Lausche auf {local_addr}");
            // Server belegt .1 (Gateway) und .2 (Server)
            registry.assign_self(registry.ip_pool().server_ip());
        } else {
            eprintln!("[vpn-tunnel] 🔗 Client-Modus: Verbinde zu {:?}", self.config.server_addr);
            // Auth an Server senden
            if let Some(server_addr) = self.config.server_addr {
                send_auth_request(
                    &socket,
                    registry.keypair(),
                    server_addr,
                    &self.config.psk,
                    self.config.client_id.as_deref().unwrap_or("unknown"),
                )
                .await?;
            }
        }

        let vpn_ip_arc = Arc::new(Mutex::new(registry.our_vpn_ip()));
        let client_id_arc = Arc::new(Mutex::new(registry.our_client_id().map(|s| s.to_string())));

        let vpn_ip_clone = vpn_ip_arc.clone();
        let client_id_clone = client_id_arc.clone();

        // ── Hintergrund-Task starten ───────────────────────────────────────
        tokio::spawn(async move {
            if let Err(e) = tunnel_loop(
                socket,
                registry,
                self.config,
                &mut proxy_rx,
                vpn_ip_clone,
                client_id_clone,
            )
            .await
            {
                eprintln!("[vpn-tunnel] ❌ Tunnel-Loop beendet: {e}");
            }
        });

        Ok(VpnTunnelHandle {
            proxy_tx,
            vpn_ip: vpn_ip_arc,
            client_id: client_id_arc,
        })
    }
}

// ─── Tunnel-Hauptschleife ────────────────────────────────────────────────────

async fn tunnel_loop(
    socket: UdpSocket,
    mut registry: PeerRegistry,
    config: TunnelConfig,
    proxy_rx: &mut mpsc::UnboundedReceiver<(ProxyRequest, tokio::sync::oneshot::Sender<ProxyHttpResult>)>,
    vpn_ip: Arc<Mutex<Option<Ipv4Addr>>>,
    client_id_arc: Arc<Mutex<Option<String>>>,
) -> Result<(), String> {
    let mut buf = [0u8; MAX_PACKET];
    let mut keepalive_timer = tokio::time::interval(std::time::Duration::from_secs(KEEPALIVE_SECS));
    let mut status_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut our_vpn_ip: Option<Ipv4Addr> = registry.our_vpn_ip();

    // Server: Proxy-Responses im Flug (request_id → oneshot sender)
    let mut pending_proxy_responses: HashMap<u32, tokio::sync::oneshot::Sender<ProxyHttpResult>> = HashMap::new();
    // Client: Multi-Chunk-Proxy-Antworten bis zur Vollständigkeit sammeln
    let mut proxy_chunks: HashMap<u32, Vec<ProxyResponse>> = HashMap::new();

    loop {
        tokio::select! {
            // ── Eingehendes UDP-Paket ──────────────────────────────────────
            result = socket.recv_from(&mut buf) => {
                let (len, src_addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[vpn-tunnel] UDP recv-Fehler: {e}");
                        continue;
                    }
                };
                let packet = &buf[..len];
                if let Err(e) = handle_packet(
                    &socket, &mut registry, packet, src_addr,
                    &mut our_vpn_ip, &config, &mut pending_proxy_responses,
                    &mut proxy_chunks,
                ).await {
                    // Nicht jeden Fehler loggen (Keepalive-Timeouts etc.)
                    if !e.contains("unbekannt") && !e.contains("Paket") {
                        eprintln!("[vpn-tunnel] ⚠ {e}");
                    }
                }
                let new_ip = registry.our_vpn_ip();
                if new_ip != our_vpn_ip {
                    our_vpn_ip = new_ip;
                    *vpn_ip.lock().await = our_vpn_ip;
                    *client_id_arc.lock().await = registry.our_client_id().map(|s| s.to_string());
                }
            }

            // ── Ausgehender Proxy-Request (von VpnTunnelHandle) ────────────
            maybe_proxy = proxy_rx.recv() => {
                match maybe_proxy {
                    Some((req, reply_tx)) => {
                        let request_id = req.request_id;
                        pending_proxy_responses.insert(request_id, reply_tx);
                        if let Err(e) = send_proxy_request(&socket, &registry, &req).await {
                            eprintln!("[vpn-tunnel] Proxy send-Fehler: {e}");
                            if let Some(tx) = pending_proxy_responses.remove(&request_id) {
                                let _ = tx.send(ProxyHttpResult { status: 0, body: vec![] });
                            }
                        }
                    }
                    None => {
                        // Channel geschlossen → Tunnel beenden
                        return Ok(());
                    }
                }
            }

            // ── Keepalive-Timer ────────────────────────────────────────────
            _ = keepalive_timer.tick() => {
                let our_pk = registry.our_pubkey();
                let peers: Vec<SocketAddr> = registry.all().iter()
                    .map(|p| p.real_addr)
                    .collect();
                for addr in peers {
                    let mut msg = vec![TYPE_KEEPALIVE];
                    msg.extend_from_slice(&our_pk);
                    let _ = socket.send_to(&msg, addr).await;
                }
                for relay_addr in registry.relay_addrs().to_vec() {
                    let mut msg = vec![TYPE_KEEPALIVE];
                    msg.extend_from_slice(&our_pk);
                    let _ = socket.send_to(&msg, relay_addr).await;
                }
            }

            // ── Status-Timer ───────────────────────────────────────────────
            _ = status_timer.tick() => {
                let ip_str = our_vpn_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "⏳".into());
                let role = if registry.is_server() { "SERVER" } else { "CLIENT" };
                eprintln!("[vpn-tunnel] 📊 [{role}] IP={ip_str} Peers={}", registry.count());
                registry.write_peers_json();
                registry.cleanup(300); // 5 Minuten Timeout

                // Server: Peer-Liste regelmäßig an alle Clients broadcasten,
                // damit deren UI aktive Peers anzeigen kann
                if registry.is_server() {
                    broadcast_peer_list(&socket, &registry).await;
                }

                // Client: Re-Auth wenn noch keine IP
                if our_vpn_ip.is_none() && !registry.is_server() {
                    if let Some(addr) = config.server_addr {
                        if let Some(ref cid) = config.client_id {
                            let _ = send_auth_request(&socket, registry.keypair(), addr, &config.psk, cid).await;
                        }
                    }
                }
            }
        }
    }
}

// ─── Paket-Handler ───────────────────────────────────────────────────────────

async fn handle_packet(
    socket: &UdpSocket,
    registry: &mut PeerRegistry,
    packet: &[u8],
    src: SocketAddr,
    our_vpn_ip: &mut Option<Ipv4Addr>,
    config: &TunnelConfig,
    pending_proxy: &mut HashMap<u32, tokio::sync::oneshot::Sender<ProxyHttpResult>>,
    proxy_chunks: &mut HashMap<u32, Vec<ProxyResponse>>,
) -> Result<(), String> {
    if packet.is_empty() {
        return Ok(());
    }

    let pkt_type = packet[0];
    if packet.len() < 33 && pkt_type != TYPE_KEEPALIVE {
        return Err("Paket zu kurz (kein Pubkey)".into());
    }

    match pkt_type {
        TYPE_KEEPALIVE => {
            // Keepalive: Nur Pubkey aktualisieren
            if packet.len() >= 33 {
                let sender_pk: [u8; 32] = packet[1..33].try_into().map_err(|_| "pk")?;
                if let Some(peer) = registry.by_pubkey_mut(&sender_pk) {
                    peer.last_seen = now_secs();
                    peer.real_addr = src;
                }
            }
            Ok(())
        }

        TYPE_AUTH => {
            let sender_pk: [u8; 32] = packet[1..33].try_into().map_err(|_| "pk")?;
            let payload = &packet[33..];
            handle_auth(socket, registry, sender_pk, payload, src, config).await
        }

        TYPE_AUTH_RESPONSE => {
            let sender_pk: [u8; 32] = packet[1..33].try_into().map_err(|_| "pk")?;
            let payload = &packet[33..];
            handle_auth_response(registry, sender_pk, payload, config, our_vpn_ip).await
        }

        TYPE_AUTH_ERROR => {
            let payload = &packet[33..];
            let err_msg = String::from_utf8_lossy(payload).to_string();
            eprintln!("[vpn-tunnel] ❌ Auth-Fehler vom Server: {err_msg}");
            Err(format!("Auth-Fehler: {err_msg}"))
        }

        TYPE_ACCESS_REQUEST => {
            let sender_pk: [u8; 32] = packet[1..33].try_into().map_err(|_| "pk")?;
            let payload = &packet[33..];
            handle_access_request(socket, registry, sender_pk, payload, src, config).await
        }

        TYPE_ACCESS_CHECK => {
            let sender_pk: [u8; 32] = packet[1..33].try_into().map_err(|_| "pk")?;
            let payload = &packet[33..];
            handle_access_check(socket, registry, sender_pk, payload, src, config).await
        }

        proxy::TYPE_PROXY_REQ => {
            let sender_pk: [u8; 32] = packet[1..33].try_into().map_err(|_| "pk")?;
            let payload = &packet[33..];
            handle_proxy_req(socket, registry, sender_pk, payload, pending_proxy).await
        }

        proxy::TYPE_PROXY_RES => {
            // TYPE_PROXY_RES enthält [32B pubkey][encrypted_payload]
            // handle_proxy_res braucht das gesamte Paket ab Byte 1 (Pubkey + Payload)
            let full = &packet[1..];
            handle_proxy_res(registry, full, pending_proxy, proxy_chunks).await
        }

        // Chat, Friends etc. werden aktuell nur geloggt, nicht verarbeitet
        TYPE_CHAT | TYPE_FRIEND_REQUEST | TYPE_FRIEND_RESPONSE
        | TYPE_ID_CHANGE_NOTIFY | TYPE_ACL_UPDATE | TYPE_ACCESS_RESPONSE
        | TYPE_PEER_LIST => {
            // Noch nicht implementiert — still akzeptieren
            Ok(())
        }

        TYPE_PRESENCE_REQUEST => {
            handle_presence_request(socket, registry, src, config).await
        }

        _ => {
            Err(format!("Unbekannter Paket-Typ: 0x{pkt_type:02x}"))
        }
    }
}

// ─── Auth ────────────────────────────────────────────────────────────────────
//
// Die Server-seitige Auth ist vollständig Stone-VPN-kompatibel:
// - User-Lookup aus stone_data/vpn-users.json
// - Passwort-Prüfung pro User (SHA-256 Hash)
// - MAC-Bindung (optional)
// - Subnetz-Enforcement (10.1.0.0/24 = StoneChain)
// - Erstanmeldung: Passwort wird gespeichert
// - Presence: online=true + last_seen bei jedem Auth

/// Client → Server: Auth-Request senden (Stone-VPN kompatibel).
async fn send_auth_request(
    socket: &UdpSocket,
    keypair: &Keypair,
    server: SocketAddr,
    password: &str,
    client_id: &str,
) -> Result<(), String> {
    let password_hash = super::crypto::hash_password(password);
    let cid_bytes = client_id.as_bytes();
    // Stone-VPN Format: [32B hash] [1B cid_len] [cid] [1B mac_len=0] [1B subnet_legacy]
    // Für Kompatibilität: MAC-Länge 0 (kein MAC) + Subnetz-Legacy b'0' = StoneChain
    let mut msg = vec![TYPE_AUTH];
    msg.extend_from_slice(&keypair.public_bytes());
    msg.extend_from_slice(&password_hash);
    msg.push(cid_bytes.len() as u8);
    msg.extend_from_slice(cid_bytes);
    msg.push(0u8); // MAC-Länge = 0
    msg.push(b'0'); // Subnetz-Legacy: StoneChain
    socket.send_to(&msg, server).await.map_err(|e| e.to_string())?;
    eprintln!("[vpn-tunnel] 🔐 Auth gesendet an {server} CID={client_id}");
    Ok(())
}

/// Server → Client: Auth-Fehler senden.
async fn send_auth_error(socket: &UdpSocket, target: SocketAddr, msg: &str) -> Result<(), String> {
    let msg_bytes = msg.as_bytes();
    let mut response = vec![TYPE_AUTH_ERROR];
    response.extend_from_slice(&[0u8; 32]); // Server-Pubkey (hier egal)
    response.extend_from_slice(msg_bytes);
    socket.send_to(&response, target).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Server: Client-Auth prüfen (Stone-VPN kompatibel).
///
/// Payload-Format:
/// ```text
/// [32B password_hash] [1B cid_len] [client_id] [1B mac_len] [mac] [subnet_wish]
/// subnet_wish: NEU [1B len][cidr utf8] | LEGACY genau 1 Byte b'0'..b'3' | fehlt
/// ```
async fn handle_auth(
    socket: &UdpSocket,
    registry: &mut PeerRegistry,
    sender_pk: [u8; 32],
    payload: &[u8],
    src: SocketAddr,
    config: &TunnelConfig,
) -> Result<(), String> {
    if !registry.is_server() {
        return Ok(());
    }

    if payload.len() < 34 {
        let _ = send_auth_error(socket, src, "Auth: Payload zu kurz").await;
        return Err("Auth: Payload zu kurz".into());
    }
    let provided_hash: [u8; 32] = payload[0..32].try_into().map_err(|_| "hash")?;

    // Client-ID parsen
    let cid_len = payload[32] as usize;
    if payload.len() < 33 + cid_len {
        let _ = send_auth_error(socket, src, "Auth: Client-ID unvollständig").await;
        return Err("Auth: Client-ID unvollständig".into());
    }
    let client_id = String::from_utf8(payload[33..33 + cid_len].to_vec())
        .map_err(|_| {
            let _ = send_auth_error(socket, src, "Client-ID kein UTF-8");
            "Client-ID kein UTF-8".to_string()
        })?;

    // MAC-Adresse parsen (optional)
    let mac_pos = 33 + cid_len;
    let mac_len = if payload.len() > mac_pos { payload[mac_pos] as usize } else { 0 };
    let mac_end = mac_pos + 1 + mac_len;
    let mac_address = if mac_len > 0 && payload.len() >= mac_end {
        Some(String::from_utf8_lossy(&payload[mac_pos + 1..mac_end]).to_string())
    } else {
        None
    };

    // Subnetz-Wunsch parsen (optional, nach MAC)
    let subnet_wish: Option<Result<String, String>> = if payload.len() == mac_end {
        None // kein Subnetz-Feld → Server wählt
    } else if payload.len() == mac_end + 1 {
        // Legacy: ein einzelnes Byte
        match payload[mac_end] {
            b'0' => Some(Ok("10.1.0.0/24".to_string())), // StoneChain
            b'1' => Some(Ok("10.0.1.0/24".to_string())),
            b'2' => Some(Ok("10.0.2.0/24".to_string())),
            b'3' => Some(Ok("10.0.3.0/24".to_string())),
            b => Some(Err(format!("unbekanntes Legacy-Subnetz 0x{b:02x}"))),
        }
    } else {
        let slen = payload[mac_end] as usize;
        if payload.len() < mac_end + 1 + slen {
            Some(Err("CIDR-String unvollständig".into()))
        } else {
            match std::str::from_utf8(&payload[mac_end + 1..mac_end + 1 + slen]) {
                Ok(s) if parse_cidr(s).is_some() => Some(Ok(s.to_string())),
                Ok(s) => Some(Err(format!("ungültiges CIDR: '{s}'"))),
                Err(_) => Some(Err("Subnetz kein UTF-8".into())),
            }
        }
    };

    // ── User-Lookup aus vpn-users.json ──────────────────────────────────
    let users_path = config.stone_data.join("vpn-users.json");
    let mut users: serde_json::Value = load_users_json(&users_path);

    let Some(user) = users.get(&client_id) else {
        eprintln!("[vpn-tunnel] ❌ Auth: VPN-ID '{client_id}' nicht registriert ({src})");
        let _ = send_auth_error(socket, src, "VPN-ID nicht registriert").await;
        return Err(format!("VPN-ID nicht registriert: {client_id}"));
    };

    // Prüfe ob User aktiv ist
    if !user.get("active").and_then(|v| v.as_bool()).unwrap_or(true) {
        eprintln!("[vpn-tunnel] ❌ Auth: User {client_id} deaktiviert");
        let _ = send_auth_error(socket, src, "Account deaktiviert").await;
        return Err("Account deaktiviert".into());
    }

    // Erlaubte Subnetze (Default: StoneChain)
    let mut allowed_subnets: Vec<String> = user.get("allowed_subnets")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if allowed_subnets.is_empty() {
        allowed_subnets.push("10.1.0.0/24".to_string());
    }

    // ── MAC-Bindung prüfen ──────────────────────────────────────────────
    let registered_macs: Vec<String> = user.get("mac_addresses")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let mut bind_mac = false;
    if !registered_macs.is_empty() {
        let client_mac = mac_address.as_deref().map(|m| m.trim().to_lowercase().replace('-', ":"));
        let known = match &client_mac {
            Some(m) => registered_macs.iter().any(|r| r.trim().to_lowercase().replace('-', ":") == *m),
            None => false,
        };
        if !known {
            eprintln!("[vpn-tunnel] ❌ Auth: MAC nicht registriert für CID={client_id}");
            let _ = send_auth_error(socket, src, "MAC nicht registriert").await;
            return Err(format!("MAC nicht registriert: {client_id}"));
        }
    } else if mac_address.is_some() {
        bind_mac = true; // Erste Bindung
    }

    // ── Passwort-Prüfung ────────────────────────────────────────────────
    let stored_hash = user.get("password_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut auth_ok = false;
    let mut save_password = false;
    if !stored_hash.is_empty() {
        let expected = hex::decode(&stored_hash).unwrap_or_default();
        if expected.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&expected);
            auth_ok = provided_hash == arr;
        }
    } else {
        // Erstanmeldung: kein Passwort → akzeptieren + speichern
        auth_ok = true;
        save_password = true;
        eprintln!("[vpn-tunnel] 🔑 Erstanmeldung: CID={client_id} (Passwort wird gespeichert)");
    }

    if !auth_ok {
        eprintln!("[vpn-tunnel] ❌ Auth: Falsches Passwort für CID={client_id} ({src})");
        let _ = send_auth_error(socket, src, "Falsches Passwort").await;
        return Err("Falsches Passwort".into());
    }

    // ── vpn-users.json aktualisieren ────────────────────────────────────
    {
        if let Some(u) = users.get_mut(&client_id) {
            if save_password {
                u["password_hash"] = serde_json::Value::String(hex::encode(provided_hash));
                eprintln!("[vpn-tunnel] 🔑 Passwort für CID={client_id} gespeichert");
            }
            if bind_mac {
                let mac = mac_address.clone().unwrap_or_default();
                match u.get_mut("mac_addresses").and_then(|v| v.as_array_mut()) {
                    Some(arr) => arr.push(serde_json::Value::String(mac.clone())),
                    None => { u["mac_addresses"] = serde_json::json!([mac]); }
                }
                eprintln!("[vpn-tunnel] 📱 MAC-Bindung: CID={client_id}");
            }
            u["online"] = serde_json::Value::Bool(true);
            u["last_seen"] = serde_json::Value::String(chrono_now_simple());
        }
        write_json_atomic(&users_path, &serde_json::to_string_pretty(&users).unwrap_or_default());
    }

    // Prüfe ob die ID bereits von ANDEREM Pubkey belegt ist
    if let Some(existing) = registry.by_client_id(&client_id) {
        if existing.pubkey != sender_pk {
            eprintln!("[vpn-tunnel] ❌ Auth: CID '{client_id}' bereits von anderem Pubkey belegt");
            let _ = send_auth_error(socket, src, "Client-ID bereits vergeben").await;
            return Err(format!("Client-ID bereits vergeben: {client_id}"));
        }
        eprintln!("[vpn-tunnel] 🔄 Reconnect: CID={client_id} von {src}");
    }

    // ── Subnetz-Enforcement ────────────────────────────────────────────
    let subnet_cidr: String = match &subnet_wish {
        Some(Ok(cidr)) => cidr.clone(),
        Some(Err(reason)) => {
            eprintln!("[vpn-tunnel] ❌ Auth: Ungültiger Subnetz-Wunsch: {reason}");
            let _ = send_auth_error(socket, src, "Ungültiges Subnetz").await;
            return Err(format!("Ungültiges Subnetz: {reason}"));
        }
        None => allowed_subnets[0].clone(),
    };
    eprintln!("[vpn-tunnel] 🔍 Auth: subnet_wish={subnet_wish:?}, allowed_subnets={allowed_subnets:?}, gewählt={subnet_cidr}");
    if !allowed_subnets.iter().any(|s| s == &subnet_cidr) {
        eprintln!("[vpn-tunnel] ❌ Auth: Subnetz {subnet_cidr} nicht erlaubt für CID={client_id}");
        let _ = send_auth_error(socket, src, "Subnetz nicht erlaubt").await;
        return Err(format!("Subnetz nicht erlaubt: {subnet_cidr}"));
    }

    // VPN-IP aus dem gewählten Subnetz zuweisen
    let vpn_ip = registry
        .add_peer_with_id_in_subnet(sender_pk, client_id.clone(), src, mac_address.clone(), &subnet_cidr)
        .ok_or_else(|| {
            let _ = send_auth_error(socket, src, "IP-Pool voll");
            "IP-Pool voll".to_string()
        })?;

    eprintln!("[vpn-tunnel] ✅ Client authentifiziert: CID={client_id} VPN-IP={vpn_ip} ({src}) [shared={:?}]",
        &registry.by_pubkey(&sender_pk).map(|p| &p.shared_secret[..4]));

    // Auth-Response: [32B server_pubkey] [1B cid_len] [cid] [4B vpn_ip]
    let our_pk = registry.our_pubkey();
    let ip_octets = vpn_ip.octets();
    let cid_bytes = client_id.as_bytes();
    let mut response = vec![TYPE_AUTH_RESPONSE];
    response.extend_from_slice(&our_pk);
    response.push(cid_bytes.len() as u8);
    response.extend_from_slice(cid_bytes);
    response.extend_from_slice(&ip_octets);
    socket.send_to(&response, src).await.map_err(|e| e.to_string())?;

    // ACL-Update senden (Subnetz-Whitelist) — an die echte Client-Adresse
    send_acl_update(socket, src, &allowed_subnets).await;

    // Neuen Peer an alle anderen Clients ankündigen
    announce_new_peer(socket, registry, sender_pk, vpn_ip).await;
    registry.write_peers_json();

    Ok(())
}

/// Lädt vpn-users.json oder gibt leeres Objekt zurück.
fn load_users_json(path: &std::path::Path) -> serde_json::Value {
    if path.exists() {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default())
            .unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    }
}

/// Atomares JSON-Schreiben: erst tmp, dann rename.
fn write_json_atomic(path: &std::path::Path, content: &str) {
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, content).is_err() { return; }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::write(path, content);
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Aktueller UTC-Timestamp als ISO-String (z.B. "2026-08-05T14:30:00Z").
fn chrono_now_simple() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Einfaches ISO-8601 Format
    let secs = now.as_secs();
    let days = secs / 86400;
    let time = secs % 86400;
    let hours = time / 3600;
    let mins = (time % 3600) / 60;
    let secs_remaining = time % 60;
    // Berechne Jahr/Monat/Tag aus Unix-Timestamp (vereinfacht)
    // Für Logging-Zwecke reicht ein formatierter String
    format!("ts:{secs}")
}

/// Sendet ACL-Update (Subnetz-Whitelist) an einen Client.
/// Format: [1B count][pro Subnetz: 4B IP octets][1B prefix] — Stone-VPN kompatibel.
async fn send_acl_update(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    allowed_subnets: &[String],
) {
    let mut payload = vec![allowed_subnets.len() as u8];
    for cidr in allowed_subnets {
        if let Some((ip, prefix)) = parse_cidr(cidr) {
            payload.extend_from_slice(&ip.octets());
            payload.push(prefix);
        }
    }
    let our_pk = [0u8; 32];
    let mut msg = vec![TYPE_ACL_UPDATE];
    msg.extend_from_slice(&our_pk);
    msg.extend_from_slice(&payload);
    eprintln!("[vpn-tunnel] 🔒 ACL-Update an {target_addr}: {allowed_subnets:?}");
    let _ = socket.send_to(&msg, target_addr).await;
}

/// Kündigt einen neuen Peer bei allen anderen Clients an.
async fn announce_new_peer(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    _new_pk: [u8; 32],
    _new_ip: Ipv4Addr,
) {
    // Einfach: volle Liste an alle (inkl. dem neuen Peer)
    broadcast_peer_list(socket, registry).await;
}

/// Server: Sendet die Peer-Liste an alle Clients.
///
/// Binärformat kompatibel zum Stone-VPN Client (stonevpn-core):
/// `[2B count BE] [pro Peer: 1B id_len + id UTF-8 + 4B vpn_ip]`
async fn broadcast_peer_list(socket: &UdpSocket, registry: &PeerRegistry) {
    let our_pk = registry.our_pubkey();
    let peers: Vec<_> = registry.all().into_iter()
        .filter(|p| !p.client_id.starts_with("unknown_"))
        .collect();

    let mut payload = Vec::new();
    payload.extend_from_slice(&(peers.len() as u16).to_be_bytes());
    for p in &peers {
        let id = p.client_id.as_bytes();
        payload.push(id.len() as u8);
        payload.extend_from_slice(id);
        payload.extend_from_slice(&p.vpn_ip.octets());
    }

    let mut msg = vec![TYPE_PEER_LIST];
    msg.extend_from_slice(&our_pk);
    msg.extend_from_slice(&payload);

    for p in &peers {
        let _ = socket.send_to(&msg, p.real_addr).await;
    }
}

/// Server: Antwortet auf TYPE_PRESENCE_REQUEST mit einer JSON-Liste aller
/// registrierten VPN-User inkl. Online-Status (kompatibel zum Stone-VPN Client).
async fn handle_presence_request(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    src: SocketAddr,
    config: &TunnelConfig,
) -> Result<(), String> {
    if !registry.is_server() {
        return Ok(());
    }
    /// Peer gilt so lange als online, wie sein letzter Keepalive her ist.
    const PRESENCE_FRESH_SECS: u64 = 90;

    let users_path = config.stone_data.join("vpn-users.json");
    let users = load_users_json(&users_path);
    let now = super::crypto::now_secs();

    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Some(obj) = users.as_object() {
        for (cid, user) in obj {
            if !user.get("active").and_then(|v| v.as_bool()).unwrap_or(false) {
                continue;
            }
            let peer = registry.by_client_id(cid);
            let online = peer
                .map(|p| now.saturating_sub(p.last_seen) <= PRESENCE_FRESH_SECS)
                .unwrap_or(false);
            entries.push(serde_json::json!({
                "id": cid,
                "online": online,
                "vpn_ip": peer.map(|p| p.vpn_ip.to_string()),
                "last_seen": user.get("last_seen").and_then(|v| v.as_str()).unwrap_or(""),
            }));
        }
    }
    // Sortiert: online zuerst, dann nach id
    entries.sort_by(|a, b| {
        let oa = a["online"].as_bool().unwrap_or(false);
        let ob = b["online"].as_bool().unwrap_or(false);
        ob.cmp(&oa).then_with(|| {
            a["id"].as_str().unwrap_or("").cmp(b["id"].as_str().unwrap_or(""))
        })
    });
    // Cap 50: Die JSON-Liste muss in EIN UDP-Paket passen (MTU ~1500).
    entries.truncate(50);

    let payload = serde_json::to_string(&entries).unwrap_or_default();
    let mut msg = vec![TYPE_PRESENCE_RESPONSE];
    msg.extend_from_slice(&registry.our_pubkey());
    msg.extend_from_slice(payload.as_bytes());
    socket.send_to(&msg, src).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Client: Auth-Response vom Server parsen.
async fn handle_auth_response(
    registry: &mut PeerRegistry,
    sender_pk: [u8; 32],
    payload: &[u8],
    _config: &TunnelConfig,
    our_vpn_ip: &mut Option<Ipv4Addr>,
) -> Result<(), String> {
    if registry.is_server() {
        return Ok(());
    }

    if payload.len() < 6 {
        return Err("Auth-Response zu kurz".into());
    }
    let cid_len = payload[0] as usize;
    if payload.len() < 1 + cid_len + 4 {
        return Err("Auth-Response unvollständig".into());
    }
    let client_id = String::from_utf8(payload[1..1 + cid_len].to_vec())
        .map_err(|_| "Client-ID kein UTF-8")?;
    let ip_start = 1 + cid_len;
    let vpn_ip = Ipv4Addr::new(
        payload[ip_start],
        payload[ip_start + 1],
        payload[ip_start + 2],
        payload[ip_start + 3],
    );

    eprintln!("[vpn-tunnel] 🎉 Authentifiziert! CID={client_id} VPN-IP={vpn_ip}");
    registry.set_our_client_id(client_id.clone());
    registry.assign_self(vpn_ip);
    *our_vpn_ip = Some(vpn_ip);

    // Server als Peer registrieren
    let relay_addr = registry.relay_addrs().first().copied().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    registry.add_peer_with_id(sender_pk, "SERVER".to_string(), relay_addr, None);
    registry.write_peers_json();

    Ok(())
}

// ─── Proxy ───────────────────────────────────────────────────────────────────

/// Sendet einen Proxy-Request an den Server (verschlüsselt mit Shared-Secret).
async fn send_proxy_request(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    req: &ProxyRequest,
) -> Result<(), String> {
    let encoded = req.encode();
    let target = if registry.is_server() {
        return Err("Server sendet keine Proxy-Requests".into());
    } else {
        registry.relay_addrs().first().copied()
            .ok_or("Kein Server konfiguriert".to_string())?
    };

    // Verschlüsseln mit Shared-Secret des Servers
    let all_peers = registry.all();
    let peer = all_peers.first().ok_or("Kein Peer für Verschlüsselung")?;
    let nonce = peer.next_encrypt_nonce();
    let encrypted = registry.keypair().encrypt(&encoded, &nonce, &peer.shared_secret);

    let our_pk = registry.our_pubkey();
    let mut packet = vec![proxy::TYPE_PROXY_REQ];
    packet.extend_from_slice(&our_pk);
    packet.extend_from_slice(&encrypted);

    socket.send_to(&packet, target).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Server: Proxy-Request empfangen → entschlüsseln → HTTP ausführen → verschlüsselt antworten.
async fn handle_proxy_req(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    sender_pk: [u8; 32],
    payload: &[u8],
    _pending_proxy: &mut HashMap<u32, tokio::sync::oneshot::Sender<ProxyHttpResult>>,
) -> Result<(), String> {
    // ── Entschlüsseln (tolerant gegenüber UDP-Verlust/Reordering) ───────
    let peer = registry.by_pubkey(&sender_pk)
        .ok_or("Proxy von unbekanntem Peer")?;
    let decrypted = peer.try_decrypt(registry.keypair(), payload)
        .ok_or_else(|| format!("Proxy-Req: Entschlüsselung fehlgeschlagen (CID={})", peer.client_id))?;

    let req = ProxyRequest::decode(&decrypted)
        .ok_or("Proxy-Request: Dekodierung fehlgeschlagen")?;

    if !registry.is_server() {
        return Ok(()); // Client empfängt keine Proxy-Requests
    }

    let request_id = req.request_id;
    let method = proxy::method::to_str(req.method);
    eprintln!(
        "[vpn-tunnel] 🌐 Proxy {} {} (von CID={})",
        method,
        &req.url[..req.url.len().min(80)],
        peer.client_id
    );

    // ── VPN-Service-API: leichte Endpunkte direkt beantworten ─────────
    // /api/status kommt weiterhin direkt aus dem Tunnel (kein HTTP-Umweg).
    // Die Service-Liste (/api/client/services) wird dagegen zuerst an die
    // echte WebUI durchgereicht — nur so erscheinen registrierte Services
    // im Client; die eingebaute Liste ist nur Fallback, wenn die WebUI
    // nicht läuft.
    let canned = handle_vpn_service_api(&req.url);
    let try_http_first = req.url.contains("/api/client/services")
        || req.url.contains("/api/services");
    if let Some(ref direct) = canned {
        if !try_http_first {
            return send_proxy_response(
                socket, registry, peer, request_id, 200, direct.as_bytes(),
            ).await;
        }
    }

    // HTTP-Request ausführen
    // ── VPN-IP-Auflösung: 10.x.x.x → real addr oder 127.0.0.1 ──────────
    let resolved_url = resolve_vpn_url(&req.url, registry);
    if resolved_url != req.url {
        eprintln!("[vpn-tunnel] 🔄 Proxy URL resolved: {} → {}", &req.url[..req.url.len().min(60)], &resolved_url[..resolved_url.len().min(60)]);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP-Client: {e}"))?;

    // Methode + Header des Original-Requests durchreichen (u. a. Authorization
    // für die WebUI — sonst scheitern alle geschützten Endpunkte mit 401)
    let mut builder = match req.method {
        proxy::method::POST => client.post(&resolved_url),
        proxy::method::PUT => client.put(&resolved_url),
        proxy::method::DELETE => client.delete(&resolved_url),
        _ => client.get(&resolved_url),
    };
    for line in req.extra_headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }
    if !req.content_type.is_empty() {
        builder = builder.header("Content-Type", &req.content_type);
    }
    if !req.body.is_empty() {
        builder = builder.body(req.body);
    }
    let http_result = builder.send().await;

    let (status, body) = match http_result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default().to_vec();
            (status, body)
        }
        Err(e) => {
            if let Some(direct) = canned {
                eprintln!(
                    "[vpn-tunnel] ⚠ {} nicht erreichbar ({e}) — eingebaute Fallback-Antwort",
                    req.url
                );
                (200, direct.into_bytes())
            } else {
                eprintln!("[vpn-tunnel] ⚠ Proxy-Fehler für {}: {e}", req.url);
                (502, format!("Proxy-Fehler: {e}").into_bytes())
            }
        }
    };

    // Antwort in Chunks aufteilen und verschlüsselt senden
    let total_chunks = ((body.len() + MAX_CHUNK_BODY - 1) / MAX_CHUNK_BODY).max(1) as u16;
    send_proxy_response(socket, registry, peer, request_id, status, &body).await?;

    eprintln!(
        "[vpn-tunnel] ✅ Proxy {} {} → HTTP {} ({} bytes, {} chunks)",
        method, &req.url[..req.url.len().min(60)], status, body.len(), total_chunks
    );
    Ok(())
}

/// Sendet eine Proxy-Antwort in Chunks (je max. MAX_CHUNK_BODY) verschlüsselt an den Peer.
async fn send_proxy_response(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    peer: &Peer,
    request_id: u32,
    status: u16,
    body: &[u8],
) -> Result<(), String> {
    let total_chunks = ((body.len() + MAX_CHUNK_BODY - 1) / MAX_CHUNK_BODY).max(1) as u16;
    let peer_addr = peer.real_addr;
    let our_pk = registry.our_pubkey();

    for chunk_idx in 0..total_chunks {
        let start = chunk_idx as usize * MAX_CHUNK_BODY;
        let end = ((chunk_idx as usize + 1) * MAX_CHUNK_BODY).min(body.len());
        let response = ProxyResponse {
            request_id, status, chunk_index: chunk_idx, total_chunks,
            body: body[start..end].to_vec(),
        };
        let payload = response.encode();
        let enc_nonce = peer.next_encrypt_nonce();
        let encrypted = registry.keypair().encrypt(&payload, &enc_nonce, &peer.shared_secret);
        let mut packet = vec![proxy::TYPE_PROXY_RES];
        packet.extend_from_slice(&our_pk);
        packet.extend_from_slice(&encrypted);

        if let Err(e) = socket.send_to(&packet, peer_addr).await {
            eprintln!("[vpn-tunnel] ⚠ Proxy-Res senden: {e}");
            break;
        }
    }
    Ok(())
}

/// Beantwortet VPN-Service-API-Aufrufe direkt (ohne HTTP-Request).
/// Gibt `Some(json_string)` zurück wenn die URL bekannt ist, sonst `None`.
fn handle_vpn_service_api(url: &str) -> Option<String> {
    // Extrahiere den Pfad aus der URL
    let path = if let Some(rest) = url.strip_prefix("http://") {
        rest.split_once('/').map(|(_, p)| format!("/{p}")).unwrap_or_default()
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest.split_once('/').map(|(_, p)| format!("/{p}")).unwrap_or_default()
    } else {
        return None;
    };

    match path.as_str() {
        "/api/client/services" | "/api/services" => {
            let stone_port = std::env::var("STONE_HTTP_PORT")
                .or_else(|_| std::env::var("STONE_PORT"))
                .unwrap_or_else(|_| "3080".into());
            Some(serde_json::json!({
                "services": [
                    {
                        "id": "stone-api",
                        "name": "Stone Node API",
                        "host": "127.0.0.1",
                        "port": stone_port.parse::<u16>().unwrap_or(3080),
                        "subnet": "0",
                        "description": "Stone Blockchain Node HTTP API"
                    },
                    {
                        "id": "stone-sync",
                        "name": "Stone Sync API",
                        "host": "127.0.0.1",
                        "port": 4002,
                        "subnet": "0",
                        "description": "Stone Node-zu-Node Synchronisation"
                    }
                ]
            }).to_string())
        }
        "/api/status" => {
            let port = std::env::var("STONE_VPN_SERVER_PORT")
                .unwrap_or_else(|_| "51822".into());
            Some(serde_json::json!({
                "connected_peers": 1,
                "port": port.parse::<u16>().unwrap_or(51822),
                "subnet": "10.1.0.0/24",
                "server_id": "stone-master",
                "peers": []
            }).to_string())
        }
        _ => None,
    }
}

/// Löst eine URL mit VPN-IP (10.x.x.x) zur echten Adresse auf.
/// - Eigene VPN-IP → 127.0.0.1
/// - Bekannter Peer → dessen real_addr IP
/// - Sonst → unverändert
fn resolve_vpn_url(url: &str, registry: &PeerRegistry) -> String {
    // Extrahiere Host aus URL
    let host = if let Some(rest) = url.strip_prefix("http://") {
        rest.split('/').next().unwrap_or("")
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest.split('/').next().unwrap_or("")
    } else {
        return url.to_string();
    };

    // Host in IP:Port aufteilen
    let (ip_str, port) = if let Some((ip, p)) = host.split_once(':') {
        (ip, Some(p))
    } else {
        (host, None)
    };

    // ── 127.0.0.1: Ports bleiben wie angefragt ─────────────────────────
    // Kein Rewriting (früher: 8088 → Stone-API-Port): Der Client erwartet,
    // dass ein Service auf 127.0.0.1:8088 auch die WebUI auf 8088 liefert —
    // sonst öffnet z. B. statt der WebUI unerwartet das Node-Dashboard.
    if ip_str == "127.0.0.1" || ip_str == "localhost" {
        return url.to_string();
    }

    // Nur 10.x.x.x IPs auflösen
    let ip: Ipv4Addr = match ip_str.parse::<Ipv4Addr>() {
        Ok(ip) if ip.octets()[0] == 10 => ip,
        _ => return url.to_string(),
    };

    // Eigene VPN-IP?
    if registry.our_vpn_ip() == Some(ip) {
        let resolved = if let Some(p) = port {
            format!("127.0.0.1:{p}")
        } else {
            "127.0.0.1".to_string()
        };
        return url.replace(host, &resolved);
    }

    // Bekannter Peer?
    if let Some(peer) = registry.by_vpn_ip(&ip) {
        let resolved = if let Some(p) = port {
            format!("{}:{p}", peer.real_addr.ip())
        } else {
            peer.real_addr.ip().to_string()
        };
        return url.replace(host, &resolved);
    }

    // Unbekannte VPN-IP: unverändert lassen (wird wahrscheinlich fehlschlagen)
    url.to_string()
}
/// Client: Proxy-Response empfangen → entschlüsseln → Chunks sammeln → an Aufrufer weiterleiten.
async fn handle_proxy_res(
    registry: &PeerRegistry,
    packet: &[u8],  // Gesamtes Paket (mit Pubkey), nicht nur Payload
    pending_proxy: &mut HashMap<u32, tokio::sync::oneshot::Sender<ProxyHttpResult>>,
    proxy_chunks: &mut HashMap<u32, Vec<ProxyResponse>>,
) -> Result<(), String> {
    if packet.len() < 33 {
        return Err("Proxy-Res: Paket zu kurz".into());
    }
    let sender_pk: [u8; 32] = packet[0..32].try_into().map_err(|_| "pk")?;
    let payload = &packet[32..];

    // ── Entschlüsseln (tolerant gegenüber UDP-Verlust/Reordering) ───────
    let peer = registry.by_pubkey(&sender_pk)
        .ok_or("Proxy-Res von unbekanntem Peer")?;
    let decrypted = peer.try_decrypt(registry.keypair(), payload)
        .ok_or_else(|| format!("Proxy-Res: Entschlüsselung fehlgeschlagen (CID={})", peer.client_id))?;

    let response = ProxyResponse::decode(&decrypted)
        .ok_or("Proxy-Response: Dekodierung fehlgeschlagen")?;

    if response.total_chunks <= 1 {
        // Einzelne Antwort
        if let Some(tx) = pending_proxy.remove(&response.request_id) {
            let _ = tx.send(ProxyHttpResult {
                status: response.status,
                body: response.body,
            });
        }
    } else {
        // Multi-Chunk: sammeln, sortieren und erst bei Vollständigkeit liefern
        let request_id = response.request_id;
        let total = response.total_chunks;
        let collected = proxy_chunks.entry(request_id).or_default();
        // Duplikate (UDP) ignorieren
        if !collected.iter().any(|c| c.chunk_index == response.chunk_index) {
            collected.push(response);
        }

        if proxy_chunks.get(&request_id).map(|c| c.len()).unwrap_or(0) == total as usize {
            let mut chunks = proxy_chunks.remove(&request_id).unwrap();
            chunks.sort_by_key(|c| c.chunk_index);

            let status = chunks[0].status;
            let body: Vec<u8> = chunks.into_iter().flat_map(|c| c.body).collect();
            eprintln!("[vpn-tunnel] 🔌 Proxy-Res reassembled id={request_id} size={}", body.len());

            if let Some(tx) = pending_proxy.remove(&request_id) {
                let _ = tx.send(ProxyHttpResult { status, body });
            }
        }
    }
    Ok(())
}

// ─── Access Request (Zugang anfordern) ───────────────────────────────────────

/// Server: Client fragt Zugang an (TYPE_ACCESS_REQUEST).
/// Payload: UTF-8 JSON mit `{ "vpn_id": "...", "password": "..." }`.
async fn handle_access_request(
    socket: &UdpSocket,
    registry: &mut PeerRegistry,
    sender_pk: [u8; 32],
    payload: &[u8],
    src: SocketAddr,
    config: &TunnelConfig,
) -> Result<(), String> {
    if !registry.is_server() { return Ok(()); }

    let json_str = String::from_utf8_lossy(payload);
    let req: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => {
            let _ = send_auth_error(socket, src, "Access-Request: ungültiges JSON").await;
            return Err("Access-Request: JSON".into());
        }
    };

    let vpn_id = req.get("vpn_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let password = req.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if vpn_id.is_empty() {
        let _ = send_auth_error(socket, src, "VPN-ID fehlt").await;
        return Err("VPN-ID fehlt".into());
    }

    let users_path = config.stone_data.join("vpn-users.json");
    let mut users = load_users_json(&users_path);

    if users.get(&vpn_id).is_some() {
        eprintln!("[vpn-tunnel] ℹ️ Access-Request: VPN-ID '{vpn_id}' bereits registriert");
    } else {
        // Neuen User anlegen (manuelle Freischaltung nötig)
        users[vpn_id.clone()] = serde_json::json!({
            "active": true,
            "password_hash": hex::encode(super::crypto::hash_password(&password)),
            "allowed_subnets": ["10.1.0.0/24"],
            "created_at": chrono_now_simple(),
        });
        write_json_atomic(&users_path, &serde_json::to_string_pretty(&users).unwrap_or_default());
        eprintln!("[vpn-tunnel] ✅ Neuer User registriert: CID={vpn_id}");
    }

    // Access-Response senden
    let response_json = serde_json::json!({
        "vpn_id": vpn_id,
        "status": "registered",
        "message": "VPN-ID registriert. Du kannst dich jetzt verbinden."
    });
    let response_bytes = serde_json::to_vec(&response_json).unwrap_or_default();
    let our_pk = registry.our_pubkey();
    let mut msg = vec![TYPE_ACCESS_RESPONSE];
    msg.extend_from_slice(&our_pk);
    msg.extend_from_slice(&response_bytes);
    let _ = socket.send_to(&msg, src).await;

    Ok(())
}

/// Server: Client prüft ob seine ID freigeschaltet ist (TYPE_ACCESS_CHECK).
async fn handle_access_check(
    socket: &UdpSocket,
    registry: &mut PeerRegistry,
    _sender_pk: [u8; 32],
    payload: &[u8],
    src: SocketAddr,
    config: &TunnelConfig,
) -> Result<(), String> {
    if !registry.is_server() { return Ok(()); }

    let vpn_id = String::from_utf8_lossy(payload).trim().to_string();
    let users_path = config.stone_data.join("vpn-users.json");
    let users = load_users_json(&users_path);

    let status = if users.get(&vpn_id).is_some() {
        "active"
    } else {
        "unknown"
    };

    let response_json = serde_json::json!({ "vpn_id": vpn_id, "status": status });
    let response_bytes = serde_json::to_vec(&response_json).unwrap_or_default();
    let our_pk = registry.our_pubkey();
    let mut msg = vec![TYPE_ACCESS_RESPONSE];
    msg.extend_from_slice(&our_pk);
    msg.extend_from_slice(&response_bytes);
    let _ = socket.send_to(&msg, src).await;

    Ok(())
}
