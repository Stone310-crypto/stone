//! Reputation-System API Endpoints
//!
//! GET /api/v1/reputation/status   – Übersicht: Pool-Balance, nächste Distribution, Gesamtverteilung
//! GET /api/v1/reputation/nodes    – Alle Nodes mit Reputation-Score + Wallet
//! GET /api/v1/reputation/node/:id – Detail-Info zu einer bestimmten Node

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use stone::token::reputation;
use super::super::state::AppState;

/// GET /api/v1/reputation/status
///
/// Reputation-Übersicht: Pool-Balance, letzte Distribution, nächstes Interval, Total verteilt.
pub async fn handle_reputation_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let registry = state.node.reputation_registry.read().unwrap_or_else(|e| e.into_inner());

    let pool_balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance(reputation::NODE_OPERATOR_POOL)
    };

    let chain_height = {
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.blocks.len() as u64
    };

    let summary = registry.summary();
    let next_distribution_block = summary.last_distribution_block
        + reputation::DISTRIBUTION_INTERVAL;

    let blocks_until_distribution = if chain_height < next_distribution_block {
        next_distribution_block - chain_height
    } else {
        0
    };

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "pool_balance": pool_balance.to_string(),
        "registered_nodes": summary.registered_nodes,
        "total_distributed": summary.total_distributed.to_string(),
        "last_distribution_block": summary.last_distribution_block,
        "next_distribution_block": next_distribution_block,
        "blocks_until_distribution": blocks_until_distribution,
        "chain_height": chain_height,
        "fee_split": {
            "burn_pct": reputation::FEE_BURN_PCT,
            "validator_pct": reputation::FEE_VALIDATOR_PCT,
            "node_pool_pct": reputation::FEE_NODE_POOL_PCT,
        },
        "distribution_interval": reputation::DISTRIBUTION_INTERVAL,
    })))
}

/// GET /api/v1/reputation/nodes
///
/// Alle registrierten Nodes mit Reputation-Score, sortiert nach Score (absteigend).
pub async fn handle_reputation_nodes(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let registry = state.node.reputation_registry.read().unwrap_or_else(|e| e.into_inner());
    let mut nodes = registry.all_nodes_info();
    // Absteigend nach Score sortieren
    nodes.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "count": nodes.len(),
        "nodes": nodes,
    })))
}

/// GET /api/v1/reputation/node/:node_id
///
/// Detail-Info zu einer bestimmten Node.
pub async fn handle_reputation_node(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    let registry = state.node.reputation_registry.read().unwrap_or_else(|e| e.into_inner());

    match registry.node_info(&node_id) {
        Some(info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "node": info,
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Node '{}' nicht in Reputation-Registry", node_id),
            })),
        ),
    }
}
