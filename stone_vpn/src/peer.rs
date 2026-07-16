//! Peer-Registry: Verwaltet bekannte VPN-Peers und deren IPs.
//!
//! Jeder Peer hat:
//! - X25519 Public Key (32 Bytes) → Identität
//! - VPN-IP (10.1.0.x) → im Overlay-Netzwerk
//! - Real-IP:Port → für direkte UDP-Verbindung
//! - Via-Relay → wenn hinter NAT, welcher Relay routet

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use crate::crypto::Keypair;
use crate::ip_pool::IpPool;
use hex;
use serde_json;

#[derive(Debug, Clone)]
pub struct Peer {
    pub pubkey: [u8; 32],
    pub vpn_ip: Ipv4Addr,
    pub real_addr: SocketAddr,
    pub via_relay: Option<[u8; 32]>,
    pub last_seen: u64,
    pub shared_secret: [u8; 32],
}

pub struct PeerRegistry {
    our_keypair: Keypair,
    ip_pool: IpPool,
    /// Pubkey → Peer
    peers: HashMap<[u8; 32], Peer>,
    /// VPN-IP → Pubkey
    ip_to_pubkey: HashMap<Ipv4Addr, [u8; 32]>,
    relay_addrs: Vec<SocketAddr>,
    is_relay: bool,
    /// Unsere eigene VPN-IP (nach Zuweisung)
    our_vpn_ip: Option<Ipv4Addr>,
    /// Pfad zum stone_data Verzeichnis
    stone_data: PathBuf,
    /// NAT-Probe: true wenn Port von außen erreichbar (→ relay-fähig)
    nat_open: bool,
}

impl PeerRegistry {
    pub fn new(
        keypair: Keypair,
        ip_pool: IpPool,
        relay_addrs: Vec<SocketAddr>,
        is_relay: bool,
        stone_data: PathBuf,
    ) -> Self {
        PeerRegistry {
            our_keypair: keypair,
            ip_pool,
            peers: HashMap::new(),
            ip_to_pubkey: HashMap::new(),
            relay_addrs,
            is_relay,
            our_vpn_ip: None,
            stone_data,
            nat_open: false,
        }
    }

    pub fn our_pubkey(&self) -> [u8; 32] {
        self.our_keypair.public_bytes()
    }

    pub fn our_vpn_ip(&self) -> Option<Ipv4Addr> {
        self.our_vpn_ip
    }

    pub fn stone_data_path(&self) -> PathBuf {
        self.stone_data.clone()
    }

    /// Setzt unsere eigene VPN-IP (als Relay .1, als Client vom Relay zugewiesen).
    pub fn assign_self(&mut self, ip: Ipv4Addr) {
        self.our_vpn_ip = Some(ip);
    }

    pub fn add_peer(&mut self, pubkey: [u8; 32], real_addr: SocketAddr) -> Option<Ipv4Addr> {
        if let Some(existing) = self.peers.get_mut(&pubkey) {
            existing.real_addr = real_addr;
            existing.last_seen = now_secs();
            return Some(existing.vpn_ip);
        }
        let vpn_ip = self.ip_pool.assign(&pubkey)?;
        let shared_secret = self.our_keypair.shared_secret(&pubkey);
        let peer = Peer {
            pubkey, vpn_ip, real_addr,
            via_relay: None,
            last_seen: now_secs(),
            shared_secret,
        };
        self.ip_to_pubkey.insert(vpn_ip, pubkey);
        self.peers.insert(pubkey, peer);
        Some(vpn_ip)
    }

    pub fn by_vpn_ip(&self, ip: Ipv4Addr) -> Option<&Peer> {
        self.ip_to_pubkey.get(&ip).and_then(|pk| self.peers.get(pk))
    }

    pub fn by_pubkey(&self, pubkey: &[u8; 32]) -> Option<&Peer> {
        self.peers.get(pubkey)
    }

    pub fn all(&self) -> Vec<&Peer> {
        self.peers.values().collect()
    }

    pub fn count(&self) -> usize {
        self.peers.len()
    }

    pub fn is_relay(&self) -> bool {
        self.is_relay
    }

    /// Markiert den Port als von außen erreichbar (nach NAT-Probe).
    pub fn set_nat_open(&mut self, open: bool) {
        self.nat_open = open;
        if open && !self.is_relay {
            eprintln!("🟢 NAT-Probe erfolgreich — Port ist offen, Relay-Modus aktiviert");
            self.is_relay = true;
        }
    }

    /// true wenn NAT-Probe erfolgreich war (Port offen).
    pub fn is_nat_open(&self) -> bool {
        self.nat_open
    }

    pub fn relay_addrs(&self) -> &[SocketAddr] {
        &self.relay_addrs
    }

    pub fn keypair(&self) -> &Keypair {
        &self.our_keypair
    }

    /// Schreibt die aktuelle Peer-Liste als JSON in stone_data/vpn_peers.json.
    pub fn write_peers_json(&self) {
        let path = self.stone_data.join("vpn_peers.json");
        let peers: Vec<serde_json::Value> = self.peers.values().map(|p| {
            serde_json::json!({
                "pubkey": hex::encode(p.pubkey),
                "vpn_ip": p.vpn_ip.to_string(),
                "real_addr": p.real_addr.to_string(),
                "last_seen_secs": p.last_seen,
            })
        }).collect();
        let our = serde_json::json!({
            "our_pubkey": hex::encode(self.our_pubkey()),
            "our_vpn_ip": self.our_vpn_ip.map(|ip| ip.to_string()),
            "mode": if self.is_relay { "relay" } else { "client" },
            "peers": peers,
        });
        if let Ok(json) = serde_json::to_string_pretty(&our) {
            let _ = std::fs::write(&path, json);
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
