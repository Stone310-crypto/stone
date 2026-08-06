//! VPN Services — Verwaltung der über das VPN erreichbaren Dienste.
//!
//! Wird vom Stone-VPN Dashboard unter `/api/services` abgefragt.
//! Jeder Service hat: id, name, host, port, subnet, description.
//!
//! ## Endpunkte
//! - `GET  /api/services`      — Liste aller Services
//! - `POST /api/services`      — Neuen Service registrieren
//! - `DELETE /api/services/:id` — Service löschen

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use super::super::state::AppState;

/// Ein über VPN erreichbarer Dienst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnService {
    pub id: String,
    pub name: String,
    #[serde(default = "default_host")]
    pub host: String,
    pub port: u16,
    /// Subnetz: "0"=StoneChain, "1"=Privat, "2"=Arbeit, "3"=Cloud
    #[serde(default = "default_subnet")]
    pub subnet: String,
    #[serde(default)]
    pub description: String,
}

fn default_host() -> String { "127.0.0.1".into() }
fn default_subnet() -> String { "0".into() }

/// Registry für VPN-Services (im Speicher).
#[derive(Clone)]
pub struct VpnServiceRegistry {
    services: std::sync::Arc<Mutex<Vec<VpnService>>>,
}

impl VpnServiceRegistry {
    pub fn new() -> Self {
        let services = vec![
            VpnService {
                id: "stone-api".into(),
                name: "Stone Node API".into(),
                host: "127.0.0.1".into(),
                port: std::env::var("STONE_HTTP_PORT")
                    .or_else(|_| std::env::var("STONE_PORT"))
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3080),
                subnet: "0".into(),
                description: "Stone Blockchain Node HTTP API".into(),
            },
            VpnService {
                id: "stone-sync".into(),
                name: "Stone Sync API".into(),
                host: "127.0.0.1".into(),
                port: std::env::var("STONE_SYNC_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(4002),
                subnet: "0".into(),
                description: "Stone Node-zu-Node Synchronisation".into(),
            },
        ];
        VpnServiceRegistry {
            services: Arc::new(Mutex::new(services)),
        }
    }
}

/// GET /api/services
pub async fn list_services(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let services = state.vpn_services.services.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    eprintln!("[vpn-api] GET /api/services → {} services", services.len());
    Ok(Json(serde_json::json!({
        "services": services.clone(),
    })))
}

/// POST /api/services
pub async fn add_service(
    State(state): State<AppState>,
    Json(body): Json<VpnService>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut services = state.vpn_services.services.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if body.name.is_empty() || body.port == 0 {
        return Ok(Json(serde_json::json!({
            "error": "Name und Port sind erforderlich"
        })));
    }

    let id = body.id.clone();
    if services.iter().any(|s| s.id == id) {
        return Ok(Json(serde_json::json!({
            "error": format!("Service '{}' existiert bereits", id)
        })));
    }

    services.push(body.clone());
    Ok(Json(serde_json::json!({
        "ok": true,
        "service": body,
    })))
}

/// DELETE /api/services/:id
pub async fn delete_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut services = state.vpn_services.services.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let before = services.len();
    services.retain(|s| s.id != id);

    if services.len() == before {
        return Ok(Json(serde_json::json!({
            "error": format!("Service '{}' nicht gefunden", id)
        })));
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/status — Minimaler Status-Endpoint fürs Dashboard.
pub async fn vpn_status(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let connected = state.vpn_tunnel.as_ref().map(|_| 1).unwrap_or(0);
    let port = std::env::var("STONE_VPN_SERVER_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(51822);
    let subnet = std::env::var("STONE_VPN_SUBNET")
        .unwrap_or_else(|_| "10.1.0.0/24".into());

    Json(serde_json::json!({
        "connected_peers": connected,
        "port": port,
        "subnet": subnet,
        "server_id": "stone-master",
        "peers": [],
    }))
}
