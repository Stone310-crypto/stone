//! Integrierter VPN-Manager — ersetzt die externe stonevpn Binary.

use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use stonevpn::{VpnConfig, VpnService, VpnStatusUpdate};

pub struct IntegratedVpn {
    service: Mutex<VpnService>,
    cached_status: Arc<RwLock<VpnStatusUpdate>>,
    config: RwLock<VpnConfig>,
}

impl IntegratedVpn {
    pub fn new() -> Self {
        IntegratedVpn {
            service: Mutex::new(VpnService::new()),
            cached_status: Arc::new(RwLock::new(VpnStatusUpdate {
                vpn_ip: None, peer_count: 0, tun_active: false,
                mode: "stopped".into(), updated_at: 0,
            })),
            config: RwLock::new(VpnConfig::default()),
        }
    }

    pub async fn start(&self, config: VpnConfig) -> Result<VpnStatusUpdate, String> {
        *self.config.write().unwrap() = config.clone();
        let mut service = self.service.lock().await;
        let mut status_rx = service.start(config).await?;

        let cached = self.cached_status.clone();
        tokio::spawn(async move {
            while let Some(update) = status_rx.recv().await {
                *cached.write().unwrap() = update;
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        Ok(self.cached_status.read().unwrap().clone())
    }

    pub async fn stop(&self) {
        self.service.lock().await.stop().await;
        *self.cached_status.write().unwrap() = VpnStatusUpdate {
            mode: "stopped".into(), vpn_ip: None,
            tun_active: false, peer_count: 0, updated_at: 0,
        };
    }

    pub async fn status(&self) -> VpnStatusUpdate {
        self.cached_status.read().unwrap().clone()
    }

    pub async fn is_running(&self) -> bool {
        self.service.lock().await.is_running().await
    }
}
