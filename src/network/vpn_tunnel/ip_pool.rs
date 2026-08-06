//! Multi-Subnet IP-Pool für den VPN-Tunnel.
//!
//! Standard-Subnetze: 10.1.0.0/24 (StoneChain), 10.0.1.0/24 (Privat),
//! 10.0.2.0/24 (Arbeit), 10.0.3.0/24 (Cloud).
//! Per ENV `STONE_VPN_SUBNET` auf z. B. `10.1.0.0/8` umstellbar.
//! Gateway (.1) und Server (.2) sind im primären Subnetz reserviert.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// Parst CIDR-Notation (z.B. "10.1.0.0/24") → (Netzwerk-IP, Präfix-Länge).
pub fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 30 {
        return None; // Zu kleines Subnetz
    }
    Some((ip, prefix))
}

/// Anzahl nutzbarer Host-IPs in einem Subnetz.
fn usable_hosts(prefix: u8) -> u32 {
    if prefix >= 31 {
        0
    } else {
        (1u64 << (32 - prefix)) as u32 - 2 // minus Netzwerk + Broadcast
    }
}

/// Maximale Host-ID (exklusiv) für ein Subnetz.
fn max_host(prefix: u8) -> u32 {
    if prefix >= 32 {
        return 1;
    }
    1u32 << (32 - prefix)
}

/// Reservierte Host-IDs (Gateway=.1, Server=.2) — nur für StoneChain.
fn reserved_hosts(cidr: &str) -> HashSet<u32> {
    let mut s = HashSet::new();
    if cidr == "10.1.0.0/24" || cidr.starts_with("10.1.") {
        s.insert(1);
        s.insert(2);
    }
    s
}

pub struct IpPool {
    /// Primäres Subnetz (Netzwerk-IP)
    network: Ipv4Addr,
    /// Primäre Präfix-Länge
    prefix: u8,
    /// Primäre CIDR
    primary_cidr: String,
    /// Subnetz-CIDR → belegte Host-IDs
    pools: HashMap<String, HashSet<u32>>,
}

impl IpPool {
    /// Erstellt einen neuen Multi-Subnet IP-Pool.
    /// Primäres Subnetz aus ENV `STONE_VPN_SUBNET` (Default: 10.1.0.0/24).
    pub fn new() -> Self {
        let cidr = std::env::var("STONE_VPN_SUBNET").unwrap_or_else(|_| "10.1.0.0/24".into());
        let (network, prefix) = parse_cidr(&cidr).unwrap_or_else(|| {
            eprintln!("[vpn-tunnel] ⚠ Ungültiges STONE_VPN_SUBNET='{cidr}', verwende 10.1.0.0/24");
            (Ipv4Addr::new(10, 1, 0, 0), 24)
        });

        let mut pools = HashMap::new();
        pools.insert(cidr.clone(), reserved_hosts(&cidr));

        // Weitere Default-Subnetze vorbereiten
        for default_cidr in &["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"] {
            if *default_cidr != cidr {
                pools.insert(default_cidr.to_string(), reserved_hosts(default_cidr));
            }
        }

        eprintln!(
            "[vpn-tunnel] 🌐 Multi-Subnet IP-Pool: primary={cidr}, {} Subnetze",
            pools.len()
        );

        IpPool {
            network,
            prefix,
            primary_cidr: cidr,
            pools,
        }
    }

    /// Netzwerk-Adresse (z.B. 10.1.0.0).
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// Präfix-Länge (z.B. 24).
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Gateway-IP (.1).
    pub fn gateway_ip(&self) -> Ipv4Addr {
        let mut octets = self.network.octets();
        octets[3] = 1;
        Ipv4Addr::from(octets)
    }

    /// Server-IP (.2).
    pub fn server_ip(&self) -> Ipv4Addr {
        let mut octets = self.network.octets();
        octets[3] = 2;
        Ipv4Addr::from(octets)
    }

    /// Weist eine IP aus dem primären Subnetz zu.
    pub fn assign(&mut self, pubkey: &[u8; 32]) -> Option<Ipv4Addr> {
        self.assign_in_subnet(pubkey, &self.primary_cidr.clone())
    }

    /// Weist eine IP aus einem bestimmten Subnetz zu.
    /// Legt das Subnetz on-demand an falls es noch nicht existiert.
    pub fn assign_in_subnet(&mut self, pubkey: &[u8; 32], cidr: &str) -> Option<Ipv4Addr> {
        let (network, prefix) = parse_cidr(cidr)?;
        let max = max_host(prefix);

        let used = self.pools
            .entry(cidr.to_string())
            .or_insert_with(|| reserved_hosts(cidr));

        let start = (pubkey[0] as u32 % max.saturating_sub(3)).saturating_add(3);
        if !used.contains(&start) && start < max && start > 2 {
            used.insert(start);
            return Some(host_to_ip(network, start));
        }
        for host in 3..max {
            if !used.contains(&host) {
                used.insert(host);
                return Some(host_to_ip(network, host));
            }
        }
        None
    }

    /// Gibt eine IP wieder frei (sucht in allen Subnetzen).
    pub fn release(&mut self, ip: Ipv4Addr) {
        let ip_oct = ip.octets();
        for (cidr, used) in self.pools.iter_mut() {
            if let Some((network, _)) = parse_cidr(cidr) {
                let net_oct = network.octets();
                if ip_oct[0] == net_oct[0] && ip_oct[1] == net_oct[1] && ip_oct[2] == net_oct[2] {
                    used.remove(&(ip_oct[3] as u32));
                    return;
                }
            }
        }
    }

    /// Host-ID + Netzwerk-IP → IPv4Addr.
    fn host_to_ip(&self, host: u32) -> Ipv4Addr {
        host_to_ip(self.network, host)
    }

    /// Liste aller verwalteten Subnetz-CIDRs.
    pub fn subnets(&self) -> Vec<&String> {
        self.pools.keys().collect()
    }
}

/// Host-ID + Netzwerk-IP → IPv4Addr (standalone).
fn host_to_ip(network: Ipv4Addr, host: u32) -> Ipv4Addr {
    let octets = network.octets();
    let total = (octets[0] as u32) << 24
        | (octets[1] as u32) << 16
        | (octets[2] as u32) << 8
        | host;
    Ipv4Addr::from(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr() {
        assert!(parse_cidr("10.1.0.0/24").is_some());
        assert!(parse_cidr("10.0.0.0/8").is_some());
        assert!(parse_cidr("invalid").is_none());
        assert!(parse_cidr("10.1.0.0/32").is_none());
    }

    #[test]
    fn test_assign_release() {
        let mut pool = IpPool::new();
        let pk = [0x42u8; 32];
        let ip = pool.assign(&pk);
        assert!(ip.is_some());
        let ip = ip.unwrap();
        pool.release(ip);
    }

    #[test]
    fn test_multi_subnet() {
        let mut pool = IpPool::new();
        let pk = [0x42u8; 32];
        let ip = pool.assign_in_subnet(&pk, "10.0.1.0/24");
        assert!(ip.is_some());
        let ip = ip.unwrap();
        assert_eq!(ip.octets()[0], 10);
        assert_eq!(ip.octets()[1], 0);
        assert_eq!(ip.octets()[2], 1);
        pool.release(ip);
    }
}
