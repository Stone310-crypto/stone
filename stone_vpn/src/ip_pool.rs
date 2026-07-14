//! IP-Pool: Verwaltet die Vergabe von VPN-IPs aus einem /24-Subnetz.
//!
//! Beispiel: 10.1.0.0/24 → IPs 10.1.0.1 bis 10.1.0.254
//! - 10.1.0.1 = Relay-Node (immer)
//! - 10.1.0.2..254 = Client-Nodes (dynamisch)
//!
//! Zuweisung ist deterministisch: `network_base + (pubkey[0] % 253) + 2`

use std::collections::HashSet;
use std::net::Ipv4Addr;

pub struct IpPool {
    network: Ipv4Addr,
    assigned: HashSet<u8>, // letztes Oktett
}

impl IpPool {
    /// Erstellt einen neuen IP-Pool aus einem CIDR-String (z.B. "10.1.0.0/24").
    pub fn new(cidr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("CIDR-Format: x.x.x.x/yy".into());
        }
        let ip: Ipv4Addr = parts[0].parse().map_err(|e| format!("IP: {e}"))?;
        let prefix: u8 = parts[1].parse().map_err(|e| format!("Prefix: {e}"))?;
        if prefix != 24 {
            return Err("Nur /24 wird unterstützt".into());
        }
        Ok(IpPool { network: ip, assigned: HashSet::new() })
    }

    /// Netzwerk-Adresse (z.B. 10.1.0.0)
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// Anzahl verfügbarer IPs
    pub fn available(&self) -> usize {
        254 - self.assigned.len()
    }

    /// Weist einem Peer eine IP zu (deterministisch via Pubkey).
    /// Gibt `None` zurück wenn der Pool voll ist.
    pub fn assign(&mut self, pubkey: &[u8; 32]) -> Option<Ipv4Addr> {
        // Basis: 10.1.0.1 = Relay, 10.1.0.2+ = Clients
        let octets = self.network.octets();
        // Deterministisch: erstes Byte des Pubkeys modulo 253 + 2
        let host = (pubkey[0] as usize % 253) + 2;
        // Fallback: nächste freie IP
        let host = if self.assigned.contains(&(host as u8)) {
            (2u8..255).find(|h| !self.assigned.contains(h))?
        } else {
            host as u8
        };
        self.assigned.insert(host);
        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], host))
    }

    /// Gibt eine IP wieder frei.
    pub fn release(&mut self, ip: Ipv4Addr) {
        self.assigned.remove(&ip.octets()[3]);
    }

    /// Prüft ob eine IP noch verfügbar ist.
    pub fn is_available(&self, ip: Ipv4Addr) -> bool {
        !self.assigned.contains(&ip.octets()[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_deterministic() {
        let mut pool = IpPool::new("10.1.0.0/24").unwrap();
        let pk = [0x42u8; 32];
        let ip1 = pool.assign(&pk).unwrap();
        let ip2 = pool.assign(&pk); // gleicher Key → None (schon vergeben)
        assert!(ip2.is_none());
        pool.release(ip1);
        let ip3 = pool.assign(&pk).unwrap();
        assert_eq!(ip1, ip3); // deterministisch
    }
}
