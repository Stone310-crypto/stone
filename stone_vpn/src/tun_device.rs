use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::process::Command;

pub struct TunDevice {
    dev: Box<dyn ReadWrite>,
    ip: Ipv4Addr,
}

trait ReadWrite: Read + Write + Send + AsRawFd {}
impl<T: Read + Write + Send + AsRawFd> ReadWrite for T {}

impl TunDevice {
    pub fn create(ip: Ipv4Addr) -> Result<Self, String> {
        let mut config = tun::Configuration::default();
        config.address(ip)
            .netmask(Ipv4Addr::new(255, 255, 255, 0))
            .destination(ip) // macOS: destination = local IP für korrektes Routing
            .mtu(1400)
            .up();
        let dev = tun::create(&config).map_err(|e| format!("TUN: {e}"))?;

        // TUN fd auf non-blocking setzen, damit read() nicht blockiert
        // und wir abwechselnd lesen und schreiben können.
        Self::set_nonblocking(dev.as_raw_fd())?;

        let network = Ipv4Addr::new(ip.octets()[0], ip.octets()[1], ip.octets()[2], 0);
        Self::add_route(network, ip)?;
        eprintln!("🌐 TUN: tun0 -> {ip}/24");

        // Firewall-Regel: Traffic auf tun0 erlauben
        Self::ensure_firewall_allows_tun();

        Ok(TunDevice { dev: Box::new(dev), ip })
    }

    /// Stellt sicher, dass die lokale Firewall Traffic auf dem TUN-Device
    /// nicht blockiert. Linux: ufw oder iptables. macOS: meist kein Problem.
    fn ensure_firewall_allows_tun() {
        #[cfg(target_os = "linux")]
        {
            // 1) ufw versuchen
            if Command::new("ufw").arg("--version").output().is_ok() {
                let status = Command::new("ufw")
                    .args(["status"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                if status.contains("Status: active") {
                    // Nur hinzufügen wenn nicht schon vorhanden
                    if !status.contains("on tun0") {
                        let _ = Command::new("ufw")
                            .args(["allow", "in", "on", "tun0"])
                            .output();
                        eprintln!("🛡️  ufw: allow in on tun0");
                    }
                }
            } else {
                // 2) iptables fallback (idempotent via -C check)
                let check = Command::new("iptables")
                    .args(["-C", "INPUT", "-i", "tun0", "-j", "ACCEPT"])
                    .status();
                if check.is_err() {
                    let _ = Command::new("iptables")
                        .args(["-I", "INPUT", "-i", "tun0", "-j", "ACCEPT"])
                        .status();
                    eprintln!("🛡️  iptables: -I INPUT -i tun0 -j ACCEPT");
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            // macOS: pfctl ist meist deaktiviert. Falls aktiv, müsste man
            // /etc/pf.conf anpassen. Für Development reicht es, den Nutzer
            // darauf hinzuweisen.
        }
    }

    /// Aktiviert IP-Forwarding (für Relay-Modus nötig).
    pub fn enable_ip_forwarding() {
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("sysctl")
                .args(["-w", "net.ipv4.ip_forward=1"])
                .output();
            // NAT für VPN-Subnetz (damit Clients via Relay ins Internet kommen)
            let check = Command::new("iptables")
                .args(["-t", "nat", "-C", "POSTROUTING", "-s", "10.1.0.0/24", "-j", "MASQUERADE"])
                .status();
            if check.is_err() {
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-I", "POSTROUTING", "-s", "10.1.0.0/24", "-j", "MASQUERADE"])
                    .status();
                eprintln!("🛡️  NAT Masquerade für 10.1.0.0/24 aktiviert");
            }
        }
        #[cfg(target_os = "macos")]
        {
            // macOS: sysctl net.inet.ip.forwarding=1
            let _ = Command::new("sysctl")
                .args(["-w", "net.inet.ip.forwarding=1"])
                .output();
        }
    }

    fn set_nonblocking(fd: std::os::unix::io::RawFd) -> Result<(), String> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags < 0 {
                return Err(format!("fcntl F_GETFL: {}", std::io::Error::last_os_error()));
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(format!("fcntl F_SETFL: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    pub fn ip(&self) -> Ipv4Addr { self.ip }

    pub fn read_packet(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = [0u8; 2048];
        match self.dev.read(&mut buf) {
            Ok(n) => {
                #[cfg(target_os = "macos")]
                {
                    // macOS UTUN-Pakete haben einen 4-Byte-Header (Address Family, AF_INET=2).
                    // Wir müssen den Header entfernen, um das reine IP-Paket zu erhalten.
                    if n > 4 {
                        return Ok(buf[4..n].to_vec());
                    }
                    return Err("TUN read: packet too short (no AF header)".into());
                }
                #[cfg(not(target_os = "macos"))]
                {
                    Ok(buf[..n].to_vec())
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err("WOULDBLOCK".into())
            }
            Err(e) => Err(format!("TUN read: {e}")),
        }
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            // macOS UTUN erwartet einen 4-Byte-Header (Address Family) in
            // BIG-ENDIAN vor jedem IP-Paket (AF_INET = 2).
            let af: [u8; 4] = [0, 0, 0, 2]; // AF_INET = 2, big-endian
            let mut framed = Vec::with_capacity(4 + packet.len());
            framed.extend_from_slice(&af);
            framed.extend_from_slice(packet);
            self.dev.write_all(&framed).map_err(|e| format!("TUN write: {e}"))?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.dev.write_all(packet).map_err(|e| format!("TUN write: {e}"))
        }
    }

    fn add_route(network: Ipv4Addr, our_ip: Ipv4Addr) -> Result<(), String> {
        let net = format!("{}/24", network);
        #[cfg(target_os = "macos")]
        {
            // Alte Routen für dieses Netzwerk löschen (von früheren utun-Instanzen)
            let _ = Command::new("route").args(["-n", "delete", "-net", &net]).output();

            // Unser aktuelles Interface finden (das, was unsere IP hat)
            let our_ip_str = our_ip.to_string();
            let mut found_iface = None;
            // ifconfig -l listet alle Interfaces, dann einzeln prüfen
            let list_out = Command::new("ifconfig")
                .args(["-l"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            for iface in list_out.split_whitespace() {
                let out = Command::new("ifconfig")
                    .arg(iface)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                if out.contains(&our_ip_str) {
                    found_iface = Some(iface.to_string());
                    break;
                }
            }
            // Auch manuell utunX prüfen (manchmal nicht in -l gelistet)
            if found_iface.is_none() {
                for i in 0..30 {
                    let name = format!("utun{i}");
                    let out = Command::new("ifconfig")
                        .arg(&name)
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                        .unwrap_or_default();
                    if out.contains(&our_ip_str) {
                        found_iface = Some(name);
                        break;
                    }
                }
            }

            if let Some(ref iface) = found_iface {
                let _ = Command::new("route")
                    .args(["-n", "add", "-net", &net, "-interface", iface])
                    .output();
                eprintln!("🌐 Route: {net} -> {iface}");

                // Verify route exists (macOS sometimes silently fails)
                let check = Command::new("route")
                    .args(["-n", "get", "10.1.0.1"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                if check.contains(iface.as_str()) {
                    eprintln!("🌐 Route verified: 10.1.0.0/24 → {iface}");
                } else {
                    eprintln!("⚠️ Route verification failed, retrying…");
                    // Retry once
                    let _ = Command::new("route")
                        .args(["-n", "add", "-net", &net, "-interface", iface])
                        .output();
                }
            } else {
                // Fallback: route über .1 als Gateway
                let gw = format!("{}.{}.{}.1", network.octets()[0], network.octets()[1], network.octets()[2]);
                let _ = Command::new("route").args(["-n","add","-net",&net,&gw]).output();
                eprintln!("⚠️ Konnte TUN-Interface nicht finden — route via {gw}");
            }
        }
        #[cfg(target_os = "linux")]
        {
            // Alte Route ggf. ersetzen
            let _ = Command::new("ip").args(["route","replace",&net,"dev","tun0"]).output();
        }
        Ok(())
    }
}
