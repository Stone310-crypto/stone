//! UDP-Tunnel: Hauptschleife für Paket-Routing.
//!
//! Relay-Modus:
//!   - Akzeptiert Handshakes von Clients
//!   - Weist VPN-IPs zu
//!   - Routet Datenpakete zwischen verbundenen Clients
//!
//! Client-Modus:
//!   - Verbindet sich zu Relay-Nodes
//!   - Sendet Handshake → bekommt VPN-IP
//!   - Sendet Keepalives (alle 25s) um NAT-Mapping offen zu halten
//!   - Empfängt Daten vom Relay (von anderen Clients)

use crate::peer::PeerRegistry;
use crate::tun_device::TunDevice;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;

/// Paket-Typen
const TYPE_HANDSHAKE: u8 = 0x01;
const TYPE_DATA: u8 = 0x02;
const TYPE_KEEPALIVE: u8 = 0x03;
const TYPE_ROUTE_ANNOUNCE: u8 = 0x04;

/// Maximale Paketgröße
const MAX_PACKET: usize = 1500;

/// Keepalive-Intervall (sollte < NAT-Timeout sein, typisch 30s)
const KEEPALIVE_SECS: u64 = 25;

/// Datei in die die zugewiesene VPN-IP geschrieben wird
const VPN_IP_FILE: &str = "vpn_ip.txt";

pub struct TunnelConfig {
    pub stone_data: PathBuf,
    pub enable_tun: bool,
}

pub async fn run(socket: UdpSocket, mut registry: PeerRegistry, config: TunnelConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; MAX_PACKET];
    let mut our_vpn_ip: Option<Ipv4Addr> = None;
    let mut tun: Option<Arc<Mutex<TunDevice>>> = None;

    if !registry.is_relay() {
        // Client: Verbindung zu Relays aufbauen
        for relay_addr in registry.relay_addrs().to_vec() {
            println!("🔗 Verbinde zu Relay: {relay_addr}");
            send_handshake(&socket, registry.keypair(), relay_addr).await?;
        }
        // Warte auf IP-Zuweisung via Handshake-Response
        println!("⏳ Warte auf VPN-IP vom Relay...");
    } else {
        // Relay: unsere eigene IP ist die erste im Pool
        our_vpn_ip = Some(Ipv4Addr::new(10, 1, 0, 1));
        registry.assign_self(our_vpn_ip.unwrap());
        write_vpn_ip(&config.stone_data, our_vpn_ip.unwrap());
        if config.enable_tun {
            match TunDevice::create(our_vpn_ip.unwrap()) {
                Ok(t) => {
                    tun = Some(Arc::new(Mutex::new(t)));
                    // Relay TUN: leite empfangene Data-Pakete ins TUN
                }
                Err(e) => eprintln!("⚠️ TUN: {e} (braucht sudo)"),
            }
        }
    }

    // Keepalive-Timer
    let keepalive_interval = Duration::from_secs(KEEPALIVE_SECS);
    let mut keepalive_timer = tokio::time::interval(keepalive_interval);

    // Status-Ticker: zeigt alle 15s den aktuellen Zustand
    let mut status_timer = tokio::time::interval(Duration::from_secs(15));

    println!("🟢 VPN-Tunnel aktiv ({} peers)", registry.count());

    // ── TUN read channel (lazy init) ──────────────────────────────────
    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut tun_thread_started = false;

    // Helper: starte TUN-Reader-Thread falls noch nicht gestartet und TUN verfügbar
    let start_tun_thread = |tun: &Option<Arc<Mutex<TunDevice>>>, started: &mut bool| {
        if *started { return; }
        if let Some(tun_arc) = tun {
            let tun_clone = tun_arc.clone();
            let tx = tun_tx.clone();
            std::thread::spawn(move || {
                eprintln!("🔍 TUN-Reader-Thread gestartet");
                loop {
                    // Lock holen (kurz), lesen, lock freigeben
                    let packet = {
                        match tun_clone.try_lock() {
                            Ok(mut dev) => match dev.read_packet() {
                                Ok(p) => Some(p),
                                Err(e) if e == "WOULDBLOCK" => {
                                    drop(dev);
                                    std::thread::sleep(Duration::from_millis(5));
                                    continue;
                                }
                                Err(e) => {
                                    eprintln!("⚠️ TUN read: {e}");
                                    drop(dev);
                                    std::thread::sleep(Duration::from_millis(50));
                                    continue;
                                }
                            },
                            Err(_) => {
                                std::thread::sleep(Duration::from_millis(1));
                                continue;
                            }
                        }
                    };
                    if let Some(p) = packet {
                        if tx.send(p).is_err() { break; }
                    }
                }
                eprintln!("🔍 TUN-Reader-Thread beendet");
            });
            *started = true;
        }
    };

    // Starte TUN-Thread sofort (für Relay) oder warte auf TUN (für Client)
    start_tun_thread(&tun, &mut tun_thread_started);

    // ── Main event loop ───────────────────────────────────────────────

    let mut counter: u64 = 0;
    loop {
        tokio::select! {
            // TUN-Device: IP-Paket empfangen → via UDP weiterleiten
            maybe_packet = tun_rx.recv() => {
                match maybe_packet {
                    Some(ip_packet) => forward_tun_packet(&socket, &registry, &ip_packet).await,
                    None => return Err("TUN channel closed".into()),
                }
            }

            // Eingehendes UDP-Paket
            result = socket.recv_from(&mut buf) => {
                let (len, src_addr) = result?;
                let packet = &buf[..len];
                if let Err(e) = handle_packet(&socket, &mut registry, packet, src_addr, &mut our_vpn_ip, &config, &mut tun).await {
                    eprintln!("⚠️ UDP: {e}");
                }
                our_vpn_ip = registry.our_vpn_ip();
                // Starte TUN-Thread falls TUN gerade erstellt wurde (Client-Handshake)
                start_tun_thread(&tun, &mut tun_thread_started);
            }

            // Status-Update
            _ = status_timer.tick() => {
                let t = match our_vpn_ip {
                    Some(ip) => format!("IP:{} P:{} {}", ip, registry.count(), if tun.is_some() { "TUN✓" } else { "TUN✗" }),
                    None => format!("P:{} ⏳", registry.count()),
                };
                println!("📊 [{}] {}", if registry.is_relay() { "RELAY" } else { "CLIENT" }, t);
                // Peer-Liste als JSON speichern (für Diagnose)
                registry.write_peers_json();
                if our_vpn_ip.is_none() && !registry.is_relay() {
                    for ra in registry.relay_addrs().to_vec() {
                        let _ = send_handshake(&socket, registry.keypair(), ra).await;
                    }
                }
            }

            // Keepalive an alle bekannten Peers
            _ = keepalive_timer.tick() => {
                counter += 1;
                let our_pk = registry.our_pubkey();
                let peers: Vec<_> = registry.all().into_iter()
                    .map(|p| (p.real_addr, p.pubkey))
                    .collect();
                for (addr, _pk) in peers {
                    let mut msg = vec![TYPE_KEEPALIVE];
                    msg.extend_from_slice(&our_pk);
                    let _ = socket.send_to(&msg, addr).await;
                }
                // Verbindung zu Relays aufrechterhalten
                for relay_addr in registry.relay_addrs().to_vec() {
                    let mut msg = vec![TYPE_KEEPALIVE];
                    msg.extend_from_slice(&our_pk);
                    let _ = socket.send_to(&msg, relay_addr).await;
                }
            }
        }
    }
}

/// Verarbeitet ein eingehendes Paket.
async fn handle_packet(
    socket: &UdpSocket,
    registry: &mut PeerRegistry,
    packet: &[u8],
    src: SocketAddr,
    our_vpn_ip: &mut Option<Ipv4Addr>,
    config: &TunnelConfig,
    tun: &mut Option<Arc<Mutex<TunDevice>>>,
) -> Result<(), String> {
    if packet.is_empty() {
        return Ok(());
    }

    let pkt_type = packet[0];
    if packet.len() < 33 {
        return Err("Paket zu kurz".into());
    }
    let sender_pk: [u8; 32] = packet[1..33].try_into().map_err(|_| "pk")?;
    let payload = &packet[33..];

    match pkt_type {
        TYPE_HANDSHAKE => {
            handle_handshake(socket, registry, sender_pk, payload, src, config, tun).await
        }
        TYPE_DATA => {
            handle_data(socket, registry, sender_pk, payload, src, tun).await
        }
        TYPE_KEEPALIVE => {
            if let Some(peer) = registry.by_pubkey(&sender_pk).map(|p| p.clone()) {
                println!("💓 Keepalive von {} (VPN {})", src, peer.vpn_ip);
            }
            Ok(())
        }
        TYPE_ROUTE_ANNOUNCE => {
            handle_route_announce(registry, sender_pk, payload)
        }
        _ => Err(format!("Unbekannter Paket-Typ: {pkt_type}")),
    }
}

/// Client → Relay: "Gib mir eine VPN-IP"
async fn send_handshake(socket: &UdpSocket, keypair: &crate::crypto::Keypair, relay: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let mut msg = vec![TYPE_HANDSHAKE];
    msg.extend_from_slice(&keypair.public_bytes());
    let sent = socket.send_to(&msg, relay).await?;
    println!("👋 Handshake gesendet an {relay} ({sent} bytes)");
    Ok(())
}

/// Handshake verarbeiten.
/// Relay-Seite: Client-Pubkey registrieren → IP zuweisen → antworten.
/// Client-Seite: Antwort vom Relay parsen → VPN-IP speichern.
async fn handle_handshake(
    socket: &UdpSocket,
    registry: &mut PeerRegistry,
    sender_pk: [u8; 32],
    payload: &[u8],
    src: SocketAddr,
    config: &TunnelConfig,
    tun: &mut Option<Arc<Mutex<TunDevice>>>,
) -> Result<(), String> {
    if registry.is_relay() {
        // ── Relay: Client registrieren ──────────────────────────────
        println!("📥 Handshake empfangen von {src} (pubkey: {}…)", &hex::encode(&sender_pk)[..16]);
        if let Some(vpn_ip) = registry.add_peer(sender_pk, src) {
            println!("✅ Neuer Client: {} → VPN-IP {vpn_ip} ({}/254 vergeben)", src, registry.count());
            let our_pk = registry.our_pubkey();
            let ip_octets = vpn_ip.octets();
            let mut response = vec![TYPE_HANDSHAKE];
            response.extend_from_slice(&our_pk);
            response.extend_from_slice(&ip_octets);
            socket.send_to(&response, src).await.map_err(|e| e.to_string())?;
            announce_new_peer(socket, registry, sender_pk, vpn_ip).await?;
            registry.write_peers_json();  // Peer-Liste aktualisieren
        }
    } else {
        // ── Client: Antwort vom Relay parsen ────────────────────────
        if payload.len() >= 4 {
            let vpn_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            println!("🎉 VPN-IP zugewiesen: {vpn_ip}");
            registry.assign_self(vpn_ip);
            write_vpn_ip(&config.stone_data, vpn_ip);
            registry.add_peer(sender_pk, src);
            registry.write_peers_json();  // Peer-Liste aktualisieren
            if config.enable_tun && tun.is_none() {
                match TunDevice::create(vpn_ip) {
                    Ok(t) => *tun = Some(Arc::new(Mutex::new(t))),
                    Err(e) => eprintln!("⚠️ TUN: {e}"),
                }
            }
        }
    }
    Ok(())
}

/// Relay/Client: TYPE_DATA empfangen → ggf. ins TUN schreiben ODER forwarden.
async fn handle_data(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    sender_pk: [u8; 32],
    payload: &[u8],
    _src: SocketAddr,
    tun: &mut Option<Arc<Mutex<TunDevice>>>,
) -> Result<(), String> {
    // Relay: Daten zwischen Clients forwarden
    if registry.is_relay() && payload.len() >= 20 {
        let dst_ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
        let src_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
        let our_ip = registry.our_vpn_ip();

        // Ziel ist der Relay selbst → ins eigene TUN schreiben
        if Some(dst_ip) == our_ip {
            if let Some(ref t) = tun {
                if let Ok(mut dev) = t.try_lock() {
                    // Hex-Dump der ersten 40 Bytes vor dem TUN-Write
                    let hex_dump: String = payload.iter().take(40).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                    eprintln!("📥 Relay UDP→TUN: {}→{} proto={} len={} data=[{hex_dump}...]", src_ip, dst_ip, payload[9], payload.len());
                    dev.write_packet(payload)?;
                    return Ok(());
                } else {
                    eprintln!("⚠️ Relay TUN lock failed (write)");
                }
            } else {
                eprintln!("⚠️ Relay TUN not available");
            }
            return Ok(());
        }

        // Ziel ist ein anderer Client → forwarden
        if let Some(target) = registry.by_vpn_ip(dst_ip) {
            let mut forward = vec![TYPE_DATA];
            forward.extend_from_slice(&sender_pk);
            forward.extend_from_slice(payload);
            eprintln!("📤 Relay Peer→Peer: {}→{} len={}", src_ip, dst_ip, payload.len());
            socket.send_to(&forward, target.real_addr).await.map_err(|e| e.to_string())?;
            return Ok(());
        }

        // Ziel unbekannt
        eprintln!("📤 Relay UDP→? {}→{} ({} peers)", src_ip, dst_ip, registry.count());
        return Ok(());
    }

    // Client: empfangene Daten ins eigene TUN schreiben
    if let Some(ref t) = tun {
        if let Ok(mut dev) = t.try_lock() {
            if let Err(e) = dev.write_packet(payload) {
                eprintln!("⚠️ Client TUN write error: {e}");
            }
            if payload.len() >= 20 {
                let src = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
                let dst = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
                eprintln!("📥 Client UDP→TUN: {}→{} proto={} len={}", src, dst, payload[9], payload.len());
            }
        } else {
            eprintln!("⚠️ Client TUN lock failed (write)");
        }
    }
    Ok(())
}

/// IP-Paket vom eigenen TUN-Device: via UDP an den richtigen Peer weiterleiten.
async fn forward_tun_packet(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    ip_packet: &[u8],
) {
    if ip_packet.len() < 20 {
        return; // kein gültiges IP-Paket
    }
    let dst_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
    let src_ip = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
    let proto = ip_packet[9];
    let our_pk = registry.our_pubkey();
    let our_ip = registry.our_vpn_ip();

    // ── Anti-Reflection: Pakete die an uns selbst adressiert sind
    //     wurden von handle_data in TUN geschrieben und vom TUN-Reader
    //     wieder ausgelesen. Diese NICHT zurück forwarden (Loop!).
    if Some(dst_ip) == our_ip {
        return;
    }
    // Auch keine Pakete forwarden die von uns selbst kommen und an
    // unbekannte Ziele gehen (z.B. kernel-generierte RST/ICMP auf
    // reflektierte Pakete).
    if Some(src_ip) == our_ip && !registry.is_relay() {
        // Client: nur forwarden wenn Ziel ein VPN-Peer ist
        let is_vpn_dest = registry.by_vpn_ip(dst_ip).is_some()
            || dst_ip.octets()[0] == 10 && dst_ip.octets()[1] == 1 && dst_ip.octets()[2] == 0;
        if !is_vpn_dest {
            return;
        }
    }

    if registry.is_relay() {
        // Relay: suche Ziel-Peer im Registry
        if let Some(target) = registry.by_vpn_ip(dst_ip) {
            let mut msg = vec![TYPE_DATA];
            msg.extend_from_slice(&our_pk);
            msg.extend_from_slice(ip_packet);
            if let Err(e) = socket.send_to(&msg, target.real_addr).await {
                eprintln!("⚠️ Relay→Peer forward error: {e}");
            }
        }
        // Ziel nicht im Registry → still verwerfen (kein Log-Spam)
    } else {
        // Client: nur an Relay forwarden wenn Ziel ein VPN-Peer ist
        if dst_ip.octets()[0] == 10 && dst_ip.octets()[1] == 1 && dst_ip.octets()[2] == 0 {
            eprintln!("📤 TUN→Relay: {}→{} proto={} len={}", src_ip, dst_ip, proto, ip_packet.len());
            for relay_addr in registry.relay_addrs().to_vec() {
                let mut msg = vec![TYPE_DATA];
                msg.extend_from_slice(&our_pk);
                msg.extend_from_slice(ip_packet);
                let _ = socket.send_to(&msg, relay_addr).await;
            }
        }
        // Nicht-VPN-Ziele (Internet) werden nicht geroutet
    }
}

/// Neuer Peer wurde registriert → alle anderen informieren.
async fn announce_new_peer(
    socket: &UdpSocket,
    registry: &PeerRegistry,
    new_pk: [u8; 32],
    new_ip: std::net::Ipv4Addr,
) -> Result<(), String> {
    let our_pk = registry.our_pubkey();
    let ip_octets = new_ip.octets();

    for peer in registry.all() {
        if peer.pubkey == new_pk {
            continue; // nicht an sich selbst
        }
        let mut msg = vec![TYPE_ROUTE_ANNOUNCE];
        msg.extend_from_slice(&our_pk);
        msg.extend_from_slice(&new_pk);
        msg.extend_from_slice(&ip_octets);
        socket.send_to(&msg, peer.real_addr).await.map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Route-Announce empfangen: neuen Peer registrieren.
fn handle_route_announce(
    registry: &mut PeerRegistry,
    _sender_pk: [u8; 32],
    payload: &[u8],
) -> Result<(), String> {
    if payload.len() < 36 {
        return Err("Route-Announce zu klein".into());
    }
    let new_pk: [u8; 32] = payload[0..32].try_into().map_err(|_| "pk")?;
    let new_ip = std::net::Ipv4Addr::new(payload[32], payload[33], payload[34], payload[35]);

    println!("📍 Route-Announce: {:?} = {new_ip}", &new_pk[..4]);
    // Peer ist bereits registriert (via Relay), nur IP aktualisieren
    Ok(())
}

/// Schreibt die zugewiesene VPN-IP in stone_data/vpn_ip.txt.
pub fn write_vpn_ip(stone_data: &std::path::Path, ip: Ipv4Addr) {
    let path = stone_data.join("vpn_ip.txt");
    std::fs::create_dir_all(stone_data).ok();
    if let Err(e) = std::fs::write(&path, ip.to_string()) {
        eprintln!("⚠️ Konnte VPN-IP nicht speichern: {e}");
    } else {
        println!("📝 VPN-IP gespeichert in {}", path.display());
    }
}

/// Liest die gespeicherte VPN-IP aus stone_data/vpn_ip.txt.
pub fn read_vpn_ip(stone_data: &std::path::Path) -> Option<Ipv4Addr> {
    let path = stone_data.join("vpn_ip.txt");
    std::fs::read_to_string(&path).ok()?.trim().parse().ok()
}
