//! Snapshot HTTP handlers.
//!
//! - `GET /api/v1/snapshot/meta`     — Snapshot-Metadaten abrufen
//! - `GET /api/v1/snapshot/download` — Snapshot-Archiv herunterladen (streaming)
//! - `POST /api/v1/snapshot/create`  — Snapshot manuell erstellen (Admin)

use axum::{
    body::Body,
    extract::{State, Query},
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
                "state_root": meta.state_root,
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

    // Tatsächliche Dateigröße für Content-Length (statt Meta, die veraltet sein kann)
    let actual_size = file.metadata().await
        .map(|m| m.len())
        .unwrap_or(meta.archive_size);

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let content_disposition = format!("attachment; filename=\"{}\"", meta.filename);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zstd".to_string()),
            (header::CONTENT_DISPOSITION, content_disposition),
            (header::CONTENT_LENGTH, actual_size.to_string()),
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

// ─── State-Root Abfrage ──────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct StateRootQuery {
    /// Optionale Block-Höhe. Ohne → aktueller Ledger-State.
    pub block_height: Option<u64>,
}

/// GET /api/v1/snapshot/state_root?block_height=600
///
/// Gibt den deterministischen state_root Hash des Token-Ledgers zurück.
/// Wird für die Bootstrap-Konsensverifikation zwischen Nodes verwendet:
/// Neue Nodes fragen alle Bootstrap-Nodes nach dem state_root bei einer bestimmten
/// Block-Höhe und prüfen ob mindestens alle übereinstimmen.
pub async fn handle_snapshot_state_root(
    State(state): State<AppState>,
    Query(q): Query<StateRootQuery>,
) -> impl IntoResponse {
    let chain_height = {
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.blocks.last().map(|b| b.index).unwrap_or(0)
    };

    // Wenn eine bestimmte Block-Höhe angefragt wird, muss sie exakt mit unserer übereinstimmen.
    // Historische State-Lookups sind nicht möglich (Ledger hält nur aktuellen Stand).
    if let Some(requested) = q.block_height {
        if requested > chain_height {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "ok": false,
                    "error": format!("Angefragte Höhe {} > lokale Chain-Höhe {}", requested, chain_height),
                })),
            ).into_response();
        }
        if requested < chain_height {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "ok": false,
                    "error": format!(
                        "Historischer State-Root nicht verfügbar. Angefragt: {}, aktuell: {}. \
                         Nur der aktuelle Ledger-Stand kann abgefragt werden.",
                        requested, chain_height
                    ),
                })),
            ).into_response();
        }
    }

    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let sr = ledger.state_root();
    let accounts = ledger.account_count();
    let supply = ledger.total_supply();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "state_root": sr,
            "block_height": chain_height,
            "accounts": accounts,
            "supply": supply.to_string(),
        })),
    ).into_response()
}
