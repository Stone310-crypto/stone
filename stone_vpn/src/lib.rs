//! StoneVPN Library — Embedded Mesh VPN für die Dashboard App.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

pub mod ip_pool;
pub mod crypto;
pub mod peer;
pub mod tunnel;
pub mod tun_device;
pub mod friends;
pub mod chat;
pub mod storage;
pub mod vpn_id;
pub mod identity;
pub mod types;

pub use types::{VpnConfig, VpnStatusUpdate};

pub struct VpnService {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    status: Arc<RwLock<VpnStatusUpdate>>,
    running: Arc<RwLock<bool>>,
}

impl VpnService {
    pub fn new() -> Self {
        VpnService {
            shutdown_tx: None,
            status: Arc::new(RwLock::new(VpnStatusUpdate {
                vpn_ip: None, peer_count: 0, tun_active: false,
                mode: "client".into(), updated_at: 0,
            })),
            running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn start(&mut self, config: VpnConfig) -> Result<mpsc::UnboundedReceiver<VpnStatusUpdate>, String> {
        if *self.running.read().await {
            return Err("VPN läuft bereits".into());
        }
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (status_tx, status_rx) = mpsc::unbounded_channel::<VpnStatusUpdate>();
        let status_arc = self.status.clone();
        let running_arc = self.running.clone();

        tokio::spawn(async move {
            *running_arc.write().await = true;
            if let Err(e) = run_vpn_task(config, shutdown_rx, status_tx.clone(), status_arc).await {
                eprintln!("[vpn] Task-Fehler: {e}");
                let _ = status_tx.send(VpnStatusUpdate {
                    vpn_ip: None, peer_count: 0, tun_active: false,
                    mode: "error".into(), updated_at: now_secs(),
                });
            }
            *running_arc.write().await = false;
        });

        self.shutdown_tx = Some(shutdown_tx);
        Ok(status_rx)
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    pub async fn get_status(&self) -> VpnStatusUpdate {
        self.status.read().await.clone()
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn run_vpn_task(
    config: VpnConfig,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    status_tx: mpsc::UnboundedSender<VpnStatusUpdate>,
    status_arc: Arc<RwLock<VpnStatusUpdate>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = ip_pool::IpPool::new(&config.ip_pool)?;

    #[cfg(unix)]
    if config.relay {
        tun_device::TunDevice::enable_ip_forwarding();
    }

    let keypair = crypto::Keypair::load_or_create(&config.stone_data.to_string_lossy())
        .map_err(|e| format!("Keypair: {e}"))?;

    let socket = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", config.port)).await?;

    let relay_addrs: Vec<SocketAddr> = config.relays.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let registry = peer::PeerRegistry::new(
        keypair, pool, relay_addrs, config.relay, config.stone_data.clone(),
    );

    let tunnel_config = tunnel::TunnelConfig {
        stone_data: config.stone_data,
        enable_tun: config.enable_tun,
    };

    let mode_str = if config.relay { "relay" } else { "client" };

    tokio::select! {
        result = tunnel::run_with_status(socket, registry, tunnel_config, status_tx, status_arc, mode_str.to_string()) => {
            result
        }
        _ = &mut shutdown_rx => {
            Ok(())
        }
    }
}
