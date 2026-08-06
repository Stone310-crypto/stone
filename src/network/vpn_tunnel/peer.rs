//! Peer-Registry für den VPN-Tunnel.
//!
//! Verwaltet bekannte VPN-Peers (Pubkey, VPN-IP, Client-ID, Shared-Secret).
//! Kompatibel mit dem Stone-VPN Protokoll.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::crypto::Keypair;
use super::ip_pool::IpPool;

/// Ein VPN-Peer.
pub struct Peer {
    /// Vom Server vergebene Client-ID (VPN-ID)
    pub client_id: String,
    /// X25519 Public Key
    pub pubkey: [u8; 32],
    /// VPN-IP im Overlay-Netzwerk
    pub vpn_ip: Ipv4Addr,
    /// Reale UDP-Adresse
    pub real_addr: SocketAddr,
    /// Letzter Kontakt (Unix-Timestamp)
    pub last_seen: u64,
    /// Shared Secret (ECDH)
    pub shared_secret: [u8; 32],
    /// MAC-Adresse (für Geräte-Bindung, optional)
    pub mac_address: Option<String>,
    /// Monoton steigender Counter für Nonce (Encrypt)
    pub encrypt_counter: AtomicU64,
    /// Monoton steigender Counter für Nonce (Decrypt)
    pub decrypt_counter: AtomicU64,
}

impl Clone for Peer {
    fn clone(&self) -> Self {
        let enc = self.encrypt_counter.load(Ordering::SeqCst);
        let dec = self.decrypt_counter.load(Ordering::SeqCst);
        Peer {
            client_id: self.client_id.clone(),
            pubkey: self.pubkey,
            vpn_ip: self.vpn_ip,
            real_addr: self.real_addr,
            last_seen: self.last_seen,
            shared_secret: self.shared_secret,
            mac_address: self.mac_address.clone(),
            encrypt_counter: AtomicU64::new(enc),
            decrypt_counter: AtomicU64::new(dec),
        }
    }
}

impl Peer {
    /// Nächste Encrypt-Nonce (12 Bytes).
    pub fn next_encrypt_nonce(&self) -> [u8; 12] {
        let ctr = self.encrypt_counter.fetch_add(1, Ordering::SeqCst);
        super::crypto::make_nonce(ctr)
    }

    /// Entschlüsselt eine Nachricht dieses Peers mit Toleranz für UDP.
    ///
    /// UDP kann Pakete verlieren oder umordnen. Ein starrer Empfangszähler
    /// desynchronisiert sich dann dauerhaft (jedes weitere Paket schlägt
    /// fehl) — genau das liess Multi-Chunk-Proxy-Antworten (Service-Seiten)
    /// regelmäßig scheitern. Deshalb wird ein Fenster von Zählern probiert
    /// und der Zähler auf die gefundene Position +1 resynchronisiert.
    /// AEAD schlägt bei falscher Nonce schlicht fehl — das Probieren ist
    /// kryptographisch unbedenklich.
    pub fn try_decrypt(&self, keypair: &Keypair, payload: &[u8]) -> Option<Vec<u8>> {
        /// Wie viele Zähler maximal vorgespult werden (Paketverlust-Fenster).
        const DECRYPT_SKIP_WINDOW: u64 = 64;
        let base = self.decrypt_counter.load(Ordering::SeqCst);
        // ── Vorwärts-Fenster: normaler UDP-Verlust / Reordering ────────
        for skip in 0..DECRYPT_SKIP_WINDOW {
            let ctr = base + skip;
            let nonce = super::crypto::make_nonce(ctr);
            if let Some(plain) = keypair.decrypt(payload, &nonce, &self.shared_secret) {
                self.decrypt_counter.store(ctr + 1, Ordering::SeqCst);
                return Some(plain);
            }
        }
        // ── Neustart-Fenster: Peer hat seine Zähler resettet ───────────
        // Nach einem Neustart der Gegenstelle beginnt deren Zähler wieder
        // bei 0, während unser Empfangszähler weit vorn ist — ohne dieses
        // Fenster wäre die Session dauerhaft tot. Trade-off: alte Nonces
        // < 64 werden akzeptiert (kleines Replay-Fenster, nur alte legitime
        // Pakete), dafür heilt die Verbindung nach einem Neustart von selbst.
        for ctr in 0..DECRYPT_SKIP_WINDOW.min(base) {
            let nonce = super::crypto::make_nonce(ctr);
            if let Some(plain) = keypair.decrypt(payload, &nonce, &self.shared_secret) {
                self.decrypt_counter.store(ctr + 1, Ordering::SeqCst);
                return Some(plain);
            }
        }
        None
    }
}

/// Registry aller bekannten VPN-Peers.
pub struct PeerRegistry {
    our_keypair: Keypair,
    ip_pool: IpPool,
    /// Pubkey → Peer
    peers: HashMap<[u8; 32], Peer>,
    /// VPN-IP → Pubkey
    ip_to_pubkey: HashMap<Ipv4Addr, [u8; 32]>,
    /// Client-ID → Pubkey
    id_to_pubkey: HashMap<String, [u8; 32]>,
    /// Relay-Adressen (Server-Adressen für Clients)
    relay_addrs: Vec<SocketAddr>,
    /// Läuft diese Instanz als Server?
    is_server: bool,
    /// Unsere eigene VPN-IP
    our_vpn_ip: Option<Ipv4Addr>,
    /// Unsere eigene Client-ID
    our_client_id: Option<String>,
    /// Pfad zum stone_data Verzeichnis
    stone_data: PathBuf,
}

impl PeerRegistry {
    pub fn new(
        keypair: Keypair,
        ip_pool: IpPool,
        relay_addrs: Vec<SocketAddr>,
        is_server: bool,
        stone_data: PathBuf,
    ) -> Self {
        PeerRegistry {
            our_keypair: keypair,
            ip_pool,
            peers: HashMap::new(),
            ip_to_pubkey: HashMap::new(),
            id_to_pubkey: HashMap::new(),
            relay_addrs,
            is_server,
            our_vpn_ip: None,
            our_client_id: None,
            stone_data,
        }
    }

    // ── Accessoren ──────────────────────────────────────────────────────

    pub fn keypair(&self) -> &Keypair {
        &self.our_keypair
    }

    pub fn our_pubkey(&self) -> [u8; 32] {
        self.our_keypair.public_bytes()
    }

    pub fn our_vpn_ip(&self) -> Option<Ipv4Addr> {
        self.our_vpn_ip
    }

    pub fn our_client_id(&self) -> Option<&str> {
        self.our_client_id.as_deref()
    }

    pub fn is_server(&self) -> bool {
        self.is_server
    }

    pub fn count(&self) -> usize {
        self.peers.len()
    }

    pub fn relay_addrs(&self) -> &[SocketAddr] {
        &self.relay_addrs
    }

    pub fn stone_data_path(&self) -> &PathBuf {
        &self.stone_data
    }

    pub fn ip_pool(&self) -> &IpPool {
        &self.ip_pool
    }

    // ── Mutatoren ───────────────────────────────────────────────────────

    /// Setzt unsere eigene VPN-IP.
    pub fn assign_self(&mut self, ip: Ipv4Addr) {
        self.our_vpn_ip = Some(ip);
    }

    /// Setzt unsere Client-ID.
    pub fn set_our_client_id(&mut self, id: String) {
        self.our_client_id = Some(id);
    }

    // ── Peer-Lookups ────────────────────────────────────────────────────

    pub fn by_pubkey(&self, pk: &[u8; 32]) -> Option<&Peer> {
        self.peers.get(pk)
    }

    pub fn by_pubkey_mut(&mut self, pk: &[u8; 32]) -> Option<&mut Peer> {
        self.peers.get_mut(pk)
    }

    pub fn by_vpn_ip(&self, ip: &Ipv4Addr) -> Option<&Peer> {
        self.ip_to_pubkey.get(ip).and_then(|pk| self.peers.get(pk))
    }

    pub fn by_client_id(&self, cid: &str) -> Option<&Peer> {
        self.id_to_pubkey.get(cid).and_then(|pk| self.peers.get(pk))
    }

    pub fn all(&self) -> Vec<&Peer> {
        self.peers.values().collect()
    }

    // ── Peer-Verwaltung ─────────────────────────────────────────────────

    /// Fügt einen Peer hinzu (Server-seitig, mit Client-ID und Subnetz).
    pub fn add_peer_with_id(
        &mut self,
        pubkey: [u8; 32],
        client_id: String,
        real_addr: SocketAddr,
        mac_address: Option<String>,
    ) -> Option<Ipv4Addr> {
        // Standard: primäres Subnetz
        self.add_peer_with_id_in_subnet(pubkey, client_id, real_addr, mac_address, &self.ip_pool.subnets().first().map(|s| s.to_string()).unwrap_or_else(|| "10.1.0.0/24".into()))
    }

    /// Fügt einen Peer in einem bestimmten Subnetz hinzu.
    pub fn add_peer_with_id_in_subnet(
        &mut self,
        pubkey: [u8; 32],
        client_id: String,
        real_addr: SocketAddr,
        mac_address: Option<String>,
        subnet_cidr: &str,
    ) -> Option<Ipv4Addr> {
        // Prüfe ob ein Subnetz-Wechsel nötig ist (vor der mutable borrow)
        let need_reassign = if let Some(existing) = self.peers.get(&pubkey) {
            let current_subnet = self.ip_to_subnet(&existing.vpn_ip);
            current_subnet.as_deref() != Some(subnet_cidr)
        } else {
            false
        };

        // Bereits registriert?
        if let Some(existing) = self.peers.get_mut(&pubkey) {
            existing.real_addr = real_addr;
            existing.last_seen = super::crypto::now_secs();

            // Subnetz-Wechsel: alte IP freigeben, neue zuweisen
            if need_reassign {
                let old_ip = existing.vpn_ip;
                self.ip_to_pubkey.remove(&old_ip);
                self.ip_pool.release(old_ip);

                if let Some(new_ip) = self.ip_pool.assign_in_subnet(&pubkey, subnet_cidr) {
                    existing.vpn_ip = new_ip;
                    self.ip_to_pubkey.insert(new_ip, pubkey);
                    eprintln!("[vpn-tunnel] 🔄 Subnetz-Wechsel: CID={client_id} {old_ip} → {new_ip} ({subnet_cidr})");
                } else {
                    self.ip_to_pubkey.insert(old_ip, pubkey);
                    eprintln!("[vpn-tunnel] ⚠ Subnetz-Wechsel fehlgeschlagen (Pool voll): CID={client_id}");
                }
            }

            // Nonce-Counter bei Reconnect resetten
            existing.encrypt_counter.store(0, std::sync::atomic::Ordering::SeqCst);
            existing.decrypt_counter.store(0, std::sync::atomic::Ordering::SeqCst);

            return Some(existing.vpn_ip);
        }

        // Neuer Peer: IP aus dem gewählten Subnetz zuweisen
        let vpn_ip = self.ip_pool.assign_in_subnet(&pubkey, subnet_cidr)?;
        let shared_secret = self.our_keypair.shared_secret(&pubkey);
        let peer = Peer {
            client_id: client_id.clone(),
            pubkey,
            vpn_ip,
            real_addr,
            last_seen: super::crypto::now_secs(),
            shared_secret,
            mac_address,
            encrypt_counter: AtomicU64::new(0),
            decrypt_counter: AtomicU64::new(0),
        };
        self.ip_to_pubkey.insert(vpn_ip, pubkey);
        self.id_to_pubkey.insert(client_id, pubkey);
        self.peers.insert(pubkey, peer);
        Some(vpn_ip)
    }

    /// Entfernt einen Peer.
    pub fn remove_peer(&mut self, pubkey: &[u8; 32]) {
        if let Some(peer) = self.peers.remove(pubkey) {
            self.ip_to_pubkey.remove(&peer.vpn_ip);
            self.id_to_pubkey.remove(&peer.client_id);
            self.ip_pool.release(peer.vpn_ip);
        }
    }

    /// Ermittelt das Subnetz-CIDR einer VPN-IP.
    fn ip_to_subnet(&self, ip: &Ipv4Addr) -> Option<String> {
        for cidr in self.ip_pool.subnets() {
            if let Some((net, prefix)) = super::ip_pool::parse_cidr(cidr) {
                let net_oct = net.octets();
                let ip_oct = ip.octets();
                // Einfacher Check: erste 3 Oktette (für /24) oder Bit-Maske
                if prefix >= 24 {
                    if ip_oct[0] == net_oct[0] && ip_oct[1] == net_oct[1] && ip_oct[2] == net_oct[2] {
                        return Some(cidr.clone());
                    }
                } else if prefix >= 16 {
                    if ip_oct[0] == net_oct[0] && ip_oct[1] == net_oct[1] {
                        return Some(cidr.clone());
                    }
                } else if prefix >= 8 {
                    if ip_oct[0] == net_oct[0] {
                        return Some(cidr.clone());
                    }
                }
            }
        }
        None
    }

    /// Schreibt die Peer-Liste als JSON (für Debug/WebUI).
    pub fn write_peers_json(&self) {
        let peers: Vec<serde_json::Value> = self
            .peers
            .values()
            .map(|p| {
                serde_json::json!({
                    "client_id": p.client_id,
                    "pubkey": hex::encode(p.pubkey),
                    "vpn_ip": p.vpn_ip.to_string(),
                    "real_addr": p.real_addr.to_string(),
                    "last_seen": p.last_seen,
                    "mac": p.mac_address,
                })
            })
            .collect();
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "our_vpn_ip": self.our_vpn_ip.map(|ip| ip.to_string()),
            "our_client_id": self.our_client_id,
            "is_server": self.is_server,
            "peer_count": peers.len(),
            "peers": peers,
        }))
        .unwrap_or_default();
        let path = self.stone_data.join("vpn_peers.json");
        let _ = std::fs::write(&path, json);
    }

    /// Bereinigt Peers die länger als `timeout_secs` nicht gesehen wurden.
    pub fn cleanup(&mut self, timeout_secs: u64) -> usize {
        let now = super::crypto::now_secs();
        let stale: Vec<[u8; 32]> = self
            .peers
            .values()
            .filter(|p| now.saturating_sub(p.last_seen) > timeout_secs)
            .map(|p| p.pubkey)
            .collect();
        let count = stale.len();
        for pk in &stale {
            self.remove_peer(pk);
        }
        if count > 0 {
            eprintln!("[vpn-tunnel] 🧹 {} abgelaufene Peers entfernt", count);
        }
        count
    }
}
