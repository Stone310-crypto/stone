//! Block list and get-by-index handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use super::super::state::AppState;

#[derive(Deserialize)]
pub struct PaginationQuery {
    #[serde(default)]
    pub page: Option<u64>,
    #[serde(default)]
    pub per_page: Option<u64>,
    /// Wenn true, werden volle Block-Daten (Transaktionen, Dokumente) zurückgegeben.
    /// Default: false (nur Counts für Dashboard-Performance).
    #[serde(default)]
    pub detail: Option<bool>,
}

/// GET /api/v1/blocks  — öffentlich (Chain-Daten sind nicht vertraulich)
pub async fn handle_list_blocks(
    Query(q): Query<PaginationQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;
    let detail = q.detail.unwrap_or(false);
    let total = chain.blocks.len();
    let blocks: Vec<serde_json::Value> = if detail {
        // Volle Block-Daten (für StoneScan / Block-Explorer)
        chain.blocks.iter().rev()
            .skip(page * per_page)
            .take(per_page)
            .map(|b| serde_json::to_value(b).unwrap_or_default())
            .collect()
    } else {
        // Slim (nur Counts — für Dashboard-Performance)
        chain.blocks.iter().rev()
            .skip(page * per_page)
            .take(per_page)
            .map(|b| json!({
                "index": b.index,
                "timestamp": b.timestamp,
                "previous_hash": b.previous_hash,
                "hash": b.hash,
                "documents": b.documents.len(),
                "transactions": b.transactions.len(),
                "signer": b.signer,
            }))
            .collect()
    };
    drop(chain);
    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "total": total,
            "page": page,
            "per_page": per_page,
            "blocks": blocks,
        })),
    )
}

/// GET /api/v1/blocks/:index  — öffentlich
pub async fn handle_get_block(
    Path(index): Path<u64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let block = chain.blocks.get(index as usize).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Block nicht gefunden"})),
        )
            .into_response()
    })?.clone();
    Ok((StatusCode::OK, axum::Json(block)))
}
