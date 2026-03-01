//! Chunk-get handler (used in peer sync).

use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use stone::storage::ChunkStore;

use super::super::state::AppState;

/// GET /api/v1/chunk/:hash – Chunk-Daten abrufen (öffentlich, für Peer-Sync & Explorer)
pub async fn handle_get_chunk(
    Path(hash): Path<String>,
    State(_state): State<AppState>,
) -> Result<Response, Response> {

    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültiger Chunk-Hash"})),
        )
            .into_response());
    }

    let chunk_store = ChunkStore::new().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "ChunkStore nicht verfügbar"})),
        )
            .into_response()
    })?;
    let bytes = chunk_store.read_chunk(&hash).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Chunk nicht gefunden"})),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap())
}
