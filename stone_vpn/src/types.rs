//! Shared types used by both the library and binary.

use std::path::PathBuf;
use serde::{Serialize, Deserialize};

/// Konfiguration für den VPN.
#[derive(Debug, Clone)]
pub struct VpnConfig {
    pub ip_pool: String,
    pub port: u16,
    pub relays: String,
    pub stone_data: PathBuf,
    pub enable_tun: bool,
    pub relay: bool,
}

impl Default for VpnConfig {
    fn default() -> Self {
        VpnConfig {
            ip_pool: "10.1.0.0/24".into(),
            port: 51821,
            relays: "212.227.54.241:51821".into(),
            stone_data: PathBuf::from("./stone_data"),
            enable_tun: true,
            relay: false,
        }
    }
}

/// Status-Updates vom VPN (via Channel an die UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatusUpdate {
    pub vpn_ip: Option<String>,
    pub peer_count: usize,
    pub tun_active: bool,
    pub mode: String,
    pub updated_at: u64,
}
