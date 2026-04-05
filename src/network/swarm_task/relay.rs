// ─── Relay-Reservierungen & Auto-Discovery ───────────────────────────────────
//
// establish_relay_reservations(): Verbindung zu konfigurierten Relay-Nodes
// auto_discover_relays():         Verbundene Peers als Relay-Kandidaten testen

use libp2p::{Multiaddr, PeerId};

use super::*;

impl SwarmTask {
    /// Stellt Relay-Reservierungen bei allen konfigurierten Relay-Nodes her.
    /// Wird automatisch aufgerufen wenn AutoNAT „Private" meldet.
    pub(super) fn establish_relay_reservations(&mut self) {
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
    pub(super) fn auto_discover_relays(&mut self) {
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
}
