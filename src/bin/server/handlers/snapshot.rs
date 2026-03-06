//! Snapshot HTTP handlers.
//!
//! - `GET /api/v1/snapshot/meta`     — Snapshot-Metadaten abrufen
//! - `GET /api/v1/snapshot/download` — Snapshot-Archiv herunterladen (streaming)
//! - `POST /api/v1/snapshot/create`  — Snapshot manuell erstellen (Admin)

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;
use tokio_util::io::ReaderStream;

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

/// GET /api/v1/snapshot/meta — Gibt Metadaten des neuesten Snapshots zurück.
pub async fn handle_snapshot_meta(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    match stone::snapshot::latest_snapshot() {
        Some(meta) => (
            StatusCode::OK,
            axum::Json(json!({
                "available": true,
                "block_height": meta.block_height,
                "genesis_hash": meta.genesis_hash,
                "latest_hash": meta.latest_hash,
                "archive_hash": meta.archive_hash,
                "archive_size": meta.archive_size,
                "created_at": meta.created_at,
                "node_version": meta.node_version,
                "filename": meta.filename,
            })),
        ).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({
                "available": false,
                "error": "Kein Snapshot verfügbar"
            })),
        ).into_response(),
    }
}

/// GET /api/v1/snapshot/download — Streamt das Snapshot-Archiv (chunked, kein volles Laden in RAM).
pub async fn handle_snapshot_download(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let meta = stone::snapshot::latest_snapshot().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Kein Snapshot verfügbar"})),
        ).into_response()
    })?;

    let archive_path = stone::snapshot::snapshot_dir().join(&meta.filename);
    if !archive_path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Snapshot-Archiv nicht gefunden"})),
        ).into_response());
    }

    let file = tokio::fs::File::open(&archive_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": format!("Lesefehler: {e}")})),
        ).into_response()
    })?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let content_disposition = format!("attachment; filename=\"{}\"", meta.filename);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zstd".to_string()),
            (header::CONTENT_DISPOSITION, content_disposition),
            (header::CONTENT_LENGTH, meta.archive_size.to_string()),
        ],
        body,
    ))
}

/// POST /api/v1/snapshot/create — Erstellt einen neuen Snapshot (Admin-Aktion).
pub async fn handle_snapshot_create(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let (height, genesis, latest) = {
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let h = chain.blocks.last().map(|b| b.index).unwrap_or(0);
        let g = chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default();
        let l = chain.latest_hash.clone();
        (h, g, l)
    };

    if height < stone::snapshot::MIN_SNAPSHOT_HEIGHT {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "error": format!("Chain zu kurz für Snapshot (min. {} Blöcke)", stone::snapshot::MIN_SNAPSHOT_HEIGHT)
            })),
        ).into_response());
    }

    // Snapshot im Blocking-Thread erstellen (IO-intensiv)
    let result = tokio::task::spawn_blocking(move || {
        stone::snapshot::create_snapshot(height, &genesis, &latest)
    }).await;

    match result {
        Ok(Ok((_path, meta))) => Ok((
            StatusCode::OK,
            axum::Json(json!({
                "success": true,
                "block_height": meta.block_height,
                "archive_size": meta.archive_size,
                "filename": meta.filename,
            })),
        ).into_response()),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": format!("Snapshot-Fehler: {e}")})),
        ).into_response()),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": format!("Task-Fehler: {e}")})),
        ).into_response()),
    }
}
