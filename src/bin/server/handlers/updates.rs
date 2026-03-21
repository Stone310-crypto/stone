//! Update-Handlers – OTA-Update-System API.
//!
//! Endpoints:
//! - GET  /api/v1/updates/status          → Öffentlich: Aktueller Update-Status
//! - GET  /api/v1/updates/chunk/:index    → Öffentlich: Chunk herunterladen (für Peer-Sync)
//! - POST /api/v1/updates/publish         → Admin: Update veröffentlichen (Manifest + Chunks)
//! - POST /api/v1/updates/install         → Admin: Bereitstehendes Update installieren
//! - POST /api/v1/updates/download        → Admin: Download manuell anstoßen
//! - POST /api/v1/updates/config          → Admin: Auto-Update Konfiguration ändern

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

// ─── GET /api/v1/updates/status (öffentlich) ─────────────────────────────────

/// Gibt den aktuellen Update-Status zurück.
/// Öffentlich zugänglich – für Dashboard und Monitoring.
pub async fn handle_update_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let updater = state.updater.read().unwrap_or_else(|e| e.into_inner());
    let progress = updater.progress();
    let config = &updater.config;

    // Prüfe ob ein Docker-Update auf dem Volume wartet
    let docker_update_staged = if stone::updater::UpdateManager::is_docker() {
        let update_path = format!("{}/updates/stone-setup", stone::blockchain::data_dir());
        std::path::Path::new(&update_path).exists()
    } else {
        false
    };

    (
        StatusCode::OK,
        axum::Json(json!({
            "current_version": stone::updater::CURRENT_VERSION,
            "state": format!("{:?}", progress.state),
            "manifest": progress.manifest,
            "chunks_total": progress.chunks_total,
            "chunks_downloaded": progress.chunks_downloaded,
            "percent": progress.percent,
            "auto_download": config.auto_download,
            "auto_install": config.auto_install,
            "auto_update_hour": config.auto_update_hour,
            "trusted_keys_count": config.trusted_keys.len(),
            "docker": stone::updater::UpdateManager::is_docker(),
            "docker_update_staged": docker_update_staged,
        })),
    )
}

// ─── GET /api/v1/updates/chunk/:index (öffentlich) ───────────────────────────

/// Gibt die Rohdaten eines Update-Chunks zurück.
/// Öffentlich – damit andere Nodes Chunks herunterladen können.
pub async fn handle_update_chunk(
    State(state): State<AppState>,
    Path(index): Path<usize>,
) -> impl IntoResponse {
    let updater = state.updater.read().unwrap_or_else(|e| e.into_inner());

    match updater.get_chunk(index) {
        Some(data) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            data,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": format!("Chunk {index} nicht verfügbar") })),
        )
            .into_response(),
    }
}

// ─── POST /api/v1/updates/publish (Admin) ────────────────────────────────────

/// Empfängt ein Update (Manifest + Chunks) vom stone-publish-update CLI.
/// Validiert Signatur und speichert das Update lokal.
/// Broadcastet das Manifest per Gossipsub an alle Peers.
pub async fn handle_update_publish(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<PublishPayload>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    // Chunks dekodieren
    let mut chunk_data: Vec<(usize, Vec<u8>)> = Vec::new();
    for chunk_entry in &payload.chunks {
        let data = base64::engine::general_purpose::STANDARD.decode(&chunk_entry.data).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "error": format!("Base64-Decode Chunk {}: {e}", chunk_entry.index) })),
            )
                .into_response()
        })?;
        chunk_data.push((chunk_entry.index, data));
    }

    // Update im Manager speichern
    {
        let mut updater = state.updater.write().unwrap_or_else(|e| e.into_inner());
        updater
            .publish_update(payload.manifest.clone(), chunk_data)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "error": e })),
                )
                    .into_response()
            })?;
    }

    // Manifest per Gossipsub broadcasten
    if let Some(ref net) = state.network {
        let manifest_json = serde_json::to_vec(&payload.manifest).unwrap_or_default();
        net.publish_gossip(stone::updater::TOPIC_UPDATES, manifest_json).await;
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "status": "published",
            "version": payload.manifest.version,
            "chunks": payload.chunks.len(),
        })),
    ))
}

#[derive(Debug, Deserialize)]
pub struct PublishPayload {
    pub manifest: stone::updater::UpdateManifest,
    pub chunks: Vec<ChunkEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ChunkEntry {
    pub index: usize,
    pub data: String, // base64
}

// ─── POST /api/v1/updates/install (Admin) ────────────────────────────────────

/// Installiert ein bereitstehendes Update (Binary-Swap + Neustart).
pub async fn handle_update_install(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    // Erst verifizieren & vorbereiten falls nötig
    {
        let mut updater = state.updater.write().unwrap_or_else(|e| e.into_inner());

        if updater.state == stone::updater::UpdateState::Verifying
            || updater.state == stone::updater::UpdateState::Available
        {
            // Erst alle Chunks prüfen
            if updater.missing_chunks().is_empty() {
                updater.verify_and_prepare().map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({ "error": e })),
                    )
                        .into_response()
                })?;
            } else {
                return Err((
                    StatusCode::CONFLICT,
                    axum::Json(json!({
                        "error": "Download noch nicht abgeschlossen",
                        "missing_chunks": updater.missing_chunks(),
                    })),
                )
                    .into_response());
            }
        }

        let new_binary = updater.install().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({ "error": e })),
            )
                .into_response()
        })?;

        println!(
            "[updater] 🔄 Neustart in 2 Sekunden... (Binary: {})",
            new_binary.display()
        );
    }

    let is_docker = stone::updater::UpdateManager::is_docker();

    // Antwort senden, dann Neustart
    let resp = if is_docker {
        (
            StatusCode::OK,
            axum::Json(json!({
                "status": "installed",
                "docker": true,
                "message": "Update gestaged. Container-Restart erforderlich (docker restart <container>).",
            })),
        )
    } else {
        (
            StatusCode::OK,
            axum::Json(json!({
                "status": "installed",
                "docker": false,
                "message": "Update installiert. Node startet in 2 Sekunden neu.",
            })),
        )
    };

    // Neustart nur bei Bare-Metal (Docker: Container muss extern restartet werden)
    if !is_docker {
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            println!("[updater] 🔄 Neustart...");
            let exe = std::env::current_exe().expect("current_exe");
            let args: Vec<String> = std::env::args().collect();
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(&exe).args(&args[1..]).exec();
                eprintln!("[updater] exec fehlgeschlagen: {err}");
            }
            #[cfg(not(unix))]
            {
                std::process::exit(0);
            }
        });
    } else {
        // Docker: Prozess sauber beenden → Container wird per restart-policy neu gestartet
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            println!("[updater] 🐳 Docker: Beende Prozess für Container-Restart...");
            std::process::exit(0);
        });
    }

    Ok(resp)
}

// ─── POST /api/v1/updates/download (Admin) ───────────────────────────────────

/// Startet manuell den Download fehlender Chunks von Peers.
pub async fn handle_update_download(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let (missing, manifest, peers_urls) = {
        let updater = state.updater.read().unwrap_or_else(|e| e.into_inner());
        let missing = updater.missing_chunks();
        let manifest = updater.manifest.clone();
        let peers: Vec<String> = state
            .node
            .get_peers()
            .iter()
            .map(|p| p.url.clone())
            .collect();
        (missing, manifest, peers)
    };

    let manifest = manifest.ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            axum::Json(json!({ "error": "Kein Update-Manifest vorhanden" })),
        )
            .into_response()
    })?;

    if missing.is_empty() {
        return Ok((
            StatusCode::OK,
            axum::Json(json!({ "status": "complete", "message": "Alle Chunks bereits vorhanden" })),
        ));
    }

    let chunk_count = missing.len();

    // Download im Hintergrund starten
    let state_clone = state.clone();
    tokio::spawn(async move {
        download_missing_chunks(state_clone, missing, peers_urls).await;
    });

    Ok((
        StatusCode::ACCEPTED,
        axum::Json(json!({
            "status": "downloading",
            "version": manifest.version,
            "missing_chunks": chunk_count,
        })),
    ))
}

/// Hintergrund-Task: Lädt fehlende Chunks von bekannten Peers herunter.
async fn download_missing_chunks(
    state: AppState,
    missing: Vec<usize>,
    peer_urls: Vec<String>,
) {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    for chunk_idx in missing {
        let mut downloaded = false;

        for peer_url in &peer_urls {
            let url = format!(
                "{}/api/v1/updates/chunk/{}",
                peer_url.trim_end_matches('/'),
                chunk_idx
            );

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(data) = resp.bytes().await {
                        let mut updater = state.updater.write().unwrap_or_else(|e| e.into_inner());
                        match updater.store_chunk(chunk_idx, data.to_vec()) {
                            Ok(()) => {
                                println!(
                                    "[updater] ✓ Chunk {chunk_idx} von {peer_url} heruntergeladen"
                                );
                                downloaded = true;
                                break;
                            }
                            Err(e) => {
                                eprintln!("[updater] ✗ Chunk {chunk_idx} von {peer_url}: {e}");
                            }
                        }
                    }
                }
                Ok(resp) => {
                    eprintln!(
                        "[updater] ✗ Chunk {chunk_idx} von {peer_url}: HTTP {}",
                        resp.status()
                    );
                }
                Err(e) => {
                    eprintln!("[updater] ✗ Chunk {chunk_idx} von {peer_url}: {e}");
                }
            }
        }

        if !downloaded {
            eprintln!("[updater] ⚠ Chunk {chunk_idx} konnte von keinem Peer geladen werden");
        }
    }

    // Prüfen ob alles da ist
    let mut updater = state.updater.write().unwrap_or_else(|e| e.into_inner());
    if updater.missing_chunks().is_empty() {
        println!("[updater] ✓ Alle Chunks heruntergeladen – verifiziere...");
        match updater.verify_and_prepare() {
            Ok(()) => {
                println!("[updater] ✓ Update verifiziert und bereit zur Installation");
                if updater.config.auto_install {
                    println!("[updater] 🔄 Auto-Install aktiviert – installiere...");
                    match updater.install() {
                        Ok(path) => {
                            println!("[updater] ✅ Auto-Install: Binary → {}", path.display());
                            drop(updater);
                            // Neustart in eigenem Task
                            tokio::spawn(async {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                if stone::updater::UpdateManager::is_docker() {
                                    println!("[updater] 🐳 Docker: Beende Prozess für Container-Restart...");
                                    std::process::exit(0);
                                } else {
                                    let exe = std::env::current_exe().expect("current_exe");
                                    let args: Vec<String> = std::env::args().collect();
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::process::CommandExt;
                                        let _ = std::process::Command::new(&exe).args(&args[1..]).exec();
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        std::process::exit(0);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("[updater] ❌ Auto-Install fehlgeschlagen: {e}");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[updater] ✗ Verifizierung fehlgeschlagen: {e}");
            }
        }
    }
}

// ─── POST /api/v1/updates/config (Admin) ─────────────────────────────────────

/// Ändert die Update-Konfiguration.
pub async fn handle_update_config(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<UpdateConfigPayload>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let mut updater = state.updater.write().unwrap_or_else(|e| e.into_inner());

    if let Some(auto_download) = payload.auto_download {
        updater.config.auto_download = auto_download;
    }
    if let Some(auto_install) = payload.auto_install {
        updater.config.auto_install = auto_install;
    }
    if let Some(ref keys) = payload.add_trusted_keys {
        for key in keys {
            if !updater.config.trusted_keys.contains(key) {
                updater.config.trusted_keys.push(key.clone());
                println!("[updater] + Trusted Key: {}…", &key[..16.min(key.len())]);
            }
        }
    }
    if let Some(ref keys) = payload.remove_trusted_keys {
        for key in keys {
            updater.config.trusted_keys.retain(|k| k != key);
            println!("[updater] - Trusted Key entfernt: {}…", &key[..16.min(key.len())]);
        }
    }
    if let Some(ref hour_opt) = payload.auto_update_hour {
        updater.config.auto_update_hour = hour_opt.filter(|&h| h < 24);
        if let Some(h) = updater.config.auto_update_hour {
            println!("[updater] ⏰ Auto-Update-Stunde: {h:02}:00");
        } else {
            println!("[updater] ⏰ Auto-Update-Zeitplan deaktiviert");
        }
    }

    updater.save_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({ "error": e })),
        )
            .into_response()
    })?;

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "status": "updated",
            "config": {
                "auto_download": updater.config.auto_download,
                "auto_install": updater.config.auto_install,
                "auto_update_hour": updater.config.auto_update_hour,
                "trusted_keys_count": updater.config.trusted_keys.len(),
            }
        })),
    ))
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigPayload {
    pub auto_download: Option<bool>,
    pub auto_install: Option<bool>,
    pub add_trusted_keys: Option<Vec<String>>,
    pub remove_trusted_keys: Option<Vec<String>>,
    #[serde(default)]
    pub auto_update_hour: Option<Option<u8>>,
}
