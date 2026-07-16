//! VPN-Manager — Fragt den VPN-Status vom lokalen Stone-Node ab.
//!
//! Der VPN läuft jetzt direkt im libp2p-Swarm des Nodes (kein separater
//! Prozess, keine separate Binary). Das Dashboard fragt nur noch den
//! Status via HTTP API ab und delegiert VPN-ID-Rotation an den Node.

use serde::{Deserialize, Serialize};

/// VPN-Status vom Node (HTTP API Response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatusResponse {
    pub active: bool,
    pub vpn_id: Option<String>,
    pub display_name: String,
    pub peer_count: usize,
    pub peers: Vec<VpnPeerInfo>,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnPeerInfo {
    pub vpn_id: String,
    pub peer_id: String,
    pub display_name: String,
    pub wallet_hash: Option<String>,
    pub last_seen: u64,
}

/// Ruft den VPN-Status vom lokalen Node ab (HTTP GET /api/v1/vpn/status).
pub async fn fetch_vpn_status(node_port: u16) -> Result<VpnStatusResponse, String> {
    let url = format!("http://127.0.0.1:{}/api/v1/vpn/status", node_port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("HTTP-Client: {e}"))?;
    let resp = client.get(&url).send().await.map_err(|e| format!("VPN-Status nicht erreichbar: {e}"))?;
    let body: VpnStatusResponse = resp.json().await.map_err(|e| format!("VPN-Status Parse-Fehler: {e}"))?;
    Ok(body)
}

/// Rotiert die VPN-ID (POST /api/v1/vpn/rotate).
pub async fn rotate_vpn_id(node_port: u16, session_token: &str) -> Result<String, String> {
    let url = format!("http://127.0.0.1:{}/api/v1/vpn/rotate", node_port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP-Client: {e}"))?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session_token))
        .send()
        .await
        .map_err(|e| format!("VPN-Rotation fehlgeschlagen: {e}"))?;
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("Parse-Fehler: {e}"))?;
    body["vpn_id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| body["error"].as_str().unwrap_or("Unbekannter Fehler").to_string())
}

/// Registriert die VPN-ID beim Server (POST /api/v1/users/me/vpn-id).
pub async fn register_vpn_id(node_port: u16, session_token: &str, vpn_id: &str) -> Result<(), String> {
    let url = format!("http://127.0.0.1:{}/api/v1/users/me/vpn-id", node_port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP-Client: {e}"))?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session_token))
        .json(&serde_json::json!({"vpn_id": vpn_id}))
        .send()
        .await
        .map_err(|e| format!("VPN-ID-Registrierung fehlgeschlagen: {e}"))?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(body["error"].as_str().unwrap_or("Unbekannter Fehler").to_string());
    }
    Ok(())
}
