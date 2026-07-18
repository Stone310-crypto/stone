// ─── VPN Protocol Event Handling ──────────────────────────────────────────────
//
// Verarbeitung der VPN-Protokoll-Events im Swarm-Task:
//   - VPN-ID Announcements (Gossipsub)
//   - VPN Chat Messages (RequestResponse)
//   - VPN Friend Requests/Responses (RequestResponse)

use libp2p::{
    PeerId,
    gossipsub,
    request_response,
};
use std::time::Duration;

use super::*;
use super::super::*;
use crate::network::vpn_protocol::*;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Wie oft die eigene VPN-ID via Gossipsub angekündigt wird (Sekunden).
const VPN_ANNOUNCE_INTERVAL_SECS: u64 = 60;

/// Wie lange nicht angekündigte VPN-Peers im Cache bleiben (Sekunden).
const VPN_PEER_TIMEOUT_SECS: u64 = 300;

impl SwarmTask {
    // ── Gossipsub: VPN-ID Announce empfangen ──────────────────────────────────

    /// Verarbeitet eine eingehende VPN-ID-Ankündigung vom Gossipsub-Topic.
    pub(super) fn handle_vpn_id_gossip(
        &mut self,
        data: &[u8],
        source: PeerId,
    ) -> gossipsub::MessageAcceptance {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return gossipsub::MessageAcceptance::Ignore;
        }

        match serde_json::from_slice::<VpnIdAnnounce>(data) {
            Ok(announce) => {
                // Ignoriere eigene Ankündigungen
                if let Some(ref state) = self.vpn_id_state {
                    if announce.vpn_id == state.current_id {
                        return gossipsub::MessageAcceptance::Ignore;
                    }
                }

                let is_new = self.vpn_peers.by_vpn_id(&announce.vpn_id).is_none();
                // Aktualisiere VPN-Peer-Registry
                self.vpn_peers.upsert(&announce, source);

                if is_new {
                    println!("[vpn] 🆕 Neuer VPN-Peer: id={} name='{}' mode={} relay={} (via {source})",
                        &announce.vpn_id[..8.min(announce.vpn_id.len())],
                        announce.display_name,
                        announce.mode,
                        announce.relay_available,
                    );
                }

                // Event an die Anwendung senden
                let _ = self.event_tx.send(NetworkEvent::VpnPeerAnnounced {
                    vpn_id: announce.vpn_id,
                    peer_id: source.to_string(),
                    display_name: announce.display_name,
                    wallet_hash: announce.wallet_hash,
                });

                gossipsub::MessageAcceptance::Accept
            }
            Err(e) => {
                eprintln!("[vpn] ❌ Ungültige VPN-ID-Ankündigung von {source}: {e}");
                gossipsub::MessageAcceptance::Reject
            }
        }
    }

    // ── RequestResponse: VPN Chat ─────────────────────────────────────────────

    /// Behandelt eine eingehende VPN-Chat-Nachricht.
    pub(super) fn handle_vpn_chat_request(
        &mut self,
        request: VpnChatRequest,
        peer: PeerId,
    ) -> VpnChatResponse {
        let msg = &request.message;

        // Prüfe ob die Nachricht für uns ist
        let is_for_us = self.vpn_id_state
            .as_ref()
            .map(|s| s.is_valid(&msg.to_id))
            .unwrap_or(false);

        if is_for_us {
            // Event an die Anwendung senden
            let _ = self.event_tx.send(NetworkEvent::VpnChatReceived {
                message: msg.clone(),
                from_peer: peer.to_string(),
            });
        }

        VpnChatResponse {
            accepted: is_for_us,
            error: if is_for_us { None } else { Some("Empfänger unbekannt".into()) },
        }
    }

    /// Behandelt eine eingehende VPN-Chat-Antwort (von unserem eigenen Request).
    pub(super) fn handle_vpn_chat_response(
        &mut self,
        response: VpnChatResponse,
        request_id: request_response::OutboundRequestId,
    ) {
        if let Some(reply) = self.pending_vpn_chat.remove(&request_id) {
            let _ = reply.send(Ok(response));
        }
    }

    // ── RequestResponse: VPN Friend ───────────────────────────────────────────

    /// Behandelt eine eingehende Freundschaftsanfrage.
    pub(super) fn handle_vpn_friend_request(
        &mut self,
        request: VpnFriendRequest,
        peer: PeerId,
    ) -> VpnFriendResponse {
        // Prüfe ob die Anfrage für uns ist
        let is_for_us = self.vpn_id_state
            .as_ref()
            .map(|s| s.is_valid(&request.to_id))
            .unwrap_or(false);

        if is_for_us {
            // Event an die Anwendung senden
            let _ = self.event_tx.send(NetworkEvent::VpnFriendRequestReceived {
                request: request.clone(),
                from_peer: peer.to_string(),
            });
        }

        // Standard-Antwort: abgelehnt (die App muss manuell akzeptieren)
        VpnFriendResponse {
            request_id: request.request_id,
            accepted: false,
            from_id: self.vpn_id_state.as_ref().map(|s| s.current_id.clone()).unwrap_or_default(),
            display_name: self.vpn_id_state.as_ref().map(|s| s.display_name.clone()).unwrap_or_default(),
            wallet_hash: self.vpn_id_state.as_ref().and_then(|s| s.linked_wallet_hash.clone()).unwrap_or_default(),
            timestamp: super::super::vpn_protocol::now_secs(),
        }
    }

    /// Behandelt eine eingehende Freundschafts-Antwort.
    pub(super) fn handle_vpn_friend_response(
        &mut self,
        response: VpnFriendResponse,
        request_id: request_response::OutboundRequestId,
    ) {
        // Zuerst: Antwort auf eigenen Request
        if let Some(reply) = self.pending_vpn_friend_req.remove(&request_id) {
            let _ = reply.send(Ok(response.clone()));
            return;
        }

        // Oder: Bestätigung dass unsere Response angekommen ist
        if let Some(reply) = self.pending_vpn_friend_resp.remove(&request_id) {
            let _ = reply.send(Ok(()));
            return;
        }

        // Unerwartete Antwort → als Event weiterleiten
        let _ = self.event_tx.send(NetworkEvent::VpnFriendResponseReceived {
            response,
            from_peer: String::new(),
        });
    }

    // ── Periodische VPN-ID Ankündigung ────────────────────────────────────────

    /// Sendet periodisch eine VPN-ID-Ankündigung via Gossipsub.
    /// Wird vom Maintenance-Timer aufgerufen.
    pub(super) fn announce_vpn_id(&mut self) {
        let state = match &self.vpn_id_state {
            Some(s) => s,
            None => return,
        };

        // Rate-Limit: nur alle VPN_ANNOUNCE_INTERVAL_SECS
        if let Some(last) = self.last_vpn_announce {
            if last.elapsed() < Duration::from_secs(VPN_ANNOUNCE_INTERVAL_SECS) {
                return;
            }
        }

        // VPN-Modus aus NAT-Status ableiten
        let mode = self.vpn_mode();

        let announce = VpnIdAnnounce {
            vpn_id: state.current_id.clone(),
            peer_id: self.swarm.local_peer_id().to_string(),
            wallet_hash: state.linked_wallet_hash.clone(),
            display_name: state.display_name.clone(),
            peer_count: self.vpn_peers.count() as u32,
            relay_available: mode == VpnMode::Relay,
            mode: mode.as_str().to_string(),
            timestamp: super::super::vpn_protocol::now_secs(),
        };

        let data = match serde_json::to_vec(&announce) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[vpn] ❌ Fehler beim Serialisieren der VPN-ID-Ankündigung: {e}");
                return;
            }
        };

        let topic = vpn_id_topic();
        match self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
            Ok(_) => {
                println!("[vpn] 📡 VPN-ID angekündigt: id={} mode={} peers={} relay={}",
                    &state.current_id[..8.min(state.current_id.len())],
                    mode.as_str(),
                    self.vpn_peers.count(),
                    mode == VpnMode::Relay,
                );
            }
            Err(e) => {
                if !e.to_string().contains("InsufficientPeers") {
                    eprintln!("[vpn] ❌ Fehler beim Senden der VPN-ID-Ankündigung: {e}");
                }
            }
        };

        self.last_vpn_announce = Some(Instant::now());

        // Alte Peers aufräumen
        self.vpn_peers.cleanup(VPN_PEER_TIMEOUT_SECS);
    }

    /// Bestimmt den VPN-Modus aus dem NAT-Status.
    pub(super) fn vpn_mode(&self) -> VpnMode {
        use super::NatStatus;
        match self.nat_status {
            NatStatus::Public => VpnMode::Relay,
            NatStatus::Private => VpnMode::Client,
            NatStatus::Unknown => VpnMode::Unknown,
        }
    }

    /// Stellt sicher dass VPN aktiviert ist (Safety-Net).
    ///
    /// Wird vom AutoNAT-Event-Handler aufgerufen, wenn der NAT-Status
    /// erkannt wurde (Public/Private). Falls `maybe_start_vpn` noch nicht
    /// gelaufen ist oder fehlgeschlagen ist, wird hier eine VPN-ID
    /// generiert und der VPN automatisch aktiviert.
    pub(super) fn ensure_vpn_activated(&mut self, detected_mode: &str) {
        // Bereits aktiviert → nichts zu tun
        if self.vpn_id_state.is_some() {
            return;
        }

        println!("[vpn] ⚡ Auto-Aktivierung: NAT-Status={} → initialisiere VPN...", detected_mode);

        // Versuche VPN-ID aus Datei zu laden (stone_data/vpn_id.txt)
        let vpn_id = Self::try_load_vpn_id_from_disk()
            .unwrap_or_else(|| {
                let id = crate::network::vpn_protocol::generate_vpn_id();
                println!("[vpn] 🆕 Neue VPN-ID generiert: {}", &id[..8.min(id.len())]);
                id
            });

        let node_name = std::env::var("STONE_NODE_NAME")
            .unwrap_or_else(|_| hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "stone-node".into()));

        let mut state = crate::network::vpn_protocol::VpnIdState::new();
        state.current_id = vpn_id;
        state.display_name = node_name;
        state.mode = detected_mode.to_string();

        // VPN-ID Topic subscriben
        let topic = crate::network::vpn_protocol::vpn_id_topic();
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
            eprintln!("[vpn] ⚠ Konnte VPN-ID-Topic nicht subscriben: {e}");
        }

        self.vpn_id_state = Some(state);
        self.last_vpn_announce = None;
        self.announce_vpn_id();

        let id = self.vpn_id_state.as_ref().map(|s| &s.current_id[..]).unwrap_or("?");
        println!("[vpn] ✅ VPN auto-aktiviert: id={} mode={}", &id[..8.min(id.len())], detected_mode);
    }

    /// Versucht die VPN-ID aus stone_data/vpn_id.txt zu laden.
    fn try_load_vpn_id_from_disk() -> Option<String> {
        let data_dir = crate::blockchain::data_dir();
        let path = format!("{data_dir}/vpn_id.txt");
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let id = content.trim().to_string();
                if id.len() >= 4 {
                    println!("[vpn] 📂 VPN-ID aus Datei geladen: {}", &id[..8.min(id.len())]);
                    Some(id)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}
