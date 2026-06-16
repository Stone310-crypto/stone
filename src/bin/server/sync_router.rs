//! Public Sync Router – offenes Netzwerk-Interface (Port 4002).
//!
//! Kein API-Key nötig. Dient der Node-zu-Node Kommunikation:
//!   GET  /health            – Node-Status
//!   GET  /info              – Node-ID, Version, Peers
//!   GET  /users             – Öffentliche User-Liste (Name, ID, Wallet)
//!   GET  /resolve/{id}       – User-Suche
//!   GET  /peers             – Peer-Liste
//!   GET  /chain-info        – Block-Height + Hash für Sync
//!   GET  /blocks            – Blöcke (paginiert, für Resync)
//!   GET  /blocks/{index}     – Einzelner Block
//!   POST /sync-users        – User-Push empfangen
//!   GET  /organizations      – Organisations-Liste für Peer-Sync
//!   POST /sync-organizations – Organisations-Liste empfangen
//!   GET  /game-economy       – Game-Economy-Daten
//!   GET  /chunk/{hash}       – Chunk-Daten für Peer-Sync

use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use tower_http::cors::{Any, CorsLayer};

use super::state::AppState;

// ─── Handler ──────────────────────────────────────────────────────────────────

/// GET /health
async fn sync_health(State(state): State<AppState>) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let height = chain.blocks.len() as u64;
    let latest = chain.latest_hash.clone();
    drop(chain);

    (
        StatusCode::OK,
        axum::Json(json!({
            "status": "ok",
            "node_id": state.node.node_id,
            "block_height": height,
            "latest_hash": latest,
            "network": "testnet",
            "role": format!("{:?}", state.node.role),
        })),
    )
}

/// GET /info
async fn sync_info(State(state): State<AppState>) -> impl IntoResponse {
    let peers = state.node.get_peers();
    let peer_urls: Vec<String> = peers.iter()
        .filter(|p| p.is_healthy())
        .map(|p| p.url.clone())
        .collect();

    let sync_port = std::env::var("STONE_SYNC_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(4002);

    (
        StatusCode::OK,
        axum::Json(json!({
            "node_id": state.node.node_id,
            "version": env!("CARGO_PKG_VERSION"),
            "sync_port": sync_port,
            "http_port": std::env::var("STONE_PORT").ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(8080),
            "peer_count": peers.len(),
            "healthy_peers": peer_urls,
        })),
    )
}

/// GET /users – Öffentliche User-Liste (Name, ID, Wallet)
async fn sync_users_list(State(state): State<AppState>) -> impl IntoResponse {
    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let list: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            json!({
                "id": u.id,
                "name": u.name,
                "wallet_address": u.wallet_address,
            })
        })
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "total": list.len(),
            "users": list,
        })),
    )
}

/// GET /resolve/{identifier} – User-Suche (lokal + Chain)
async fn sync_resolve(
    Path(identifier): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let identifier = identifier.trim();
    let lower = identifier.to_lowercase();

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut seen_wallets = std::collections::HashSet::new();

    // Lokale User durchsuchen
    {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        for u in users.iter() {
            let name_match = u.name.to_lowercase().contains(&lower);
            let id_match = u.id == identifier;
            let wallet_match = !u.wallet_address.is_empty() && u.wallet_address == identifier;

            if name_match || id_match || wallet_match {
                if !u.wallet_address.is_empty() {
                    seen_wallets.insert(u.wallet_address.clone());
                }
                results.push(json!({
                    "name": u.name,
                    "user_id": u.id,
                    "wallet": u.wallet_address,
                }));
            }
        }
    }

    // On-Chain Accounts durchsuchen
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        for (wallet, name) in ledger.all_registered_accounts() {
            if seen_wallets.contains(wallet.as_str()) {
                continue;
            }
            let name_match = name.to_lowercase().contains(&lower);
            let wallet_match = wallet == identifier;
            if name_match || wallet_match {
                seen_wallets.insert(wallet.to_string());
                results.push(json!({
                    "name": name,
                    "user_id": "",
                    "wallet": wallet,
                }));
            }
        }
    }

    if results.is_empty() {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Kein User gefunden"})),
        )
    } else {
        (
            StatusCode::OK,
            axum::Json(json!({"ok": true, "results": results})),
        )
    }
}

/// GET /peers
async fn sync_peers(State(state): State<AppState>) -> impl IntoResponse {
    let peers = state.node.get_peers();
    let list: Vec<serde_json::Value> = peers
        .iter()
        .map(|p| {
            json!({
                "url": p.url,
                "name": p.name,
                "status": format!("{:?}", p.status),
                "block_height": p.block_height,
            })
        })
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({"peers": list})),
    )
}

/// GET /chain-info
async fn sync_chain_info(State(state): State<AppState>) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let height = chain.blocks.len() as u64;
    let latest = chain.latest_hash.clone();
    let genesis = chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default();
    drop(chain);

    (
        StatusCode::OK,
        axum::Json(json!({
            "block_height": height,
            "latest_hash": latest,
            "genesis_hash": genesis,
            "node_id": state.node.node_id,
        })),
    )
}

#[derive(Deserialize)]
pub struct BlockQuery {
    #[serde(default)]
    pub from: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// GET /blocks?from=0&limit=50
async fn sync_blocks(
    Query(q): Query<BlockQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let from = q.from.unwrap_or(0) as usize;
    let limit = q.limit.unwrap_or(50).min(200);
    let total = chain.blocks.len();

    let blocks: Vec<serde_json::Value> = chain.blocks
        .iter()
        .skip(from)
        .take(limit)
        .map(|b| {
            json!({
                "index": b.index,
                "hash": b.hash,
                "previous_hash": b.previous_hash,
                "timestamp": b.timestamp,
                "signer": b.signer,
                "transactions": b.transactions,
                "documents": b.documents,
            })
        })
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "from": from,
            "count": blocks.len(),
            "blocks": blocks,
        })),
    )
}

/// GET /blocks/{index}
async fn sync_block(
    Path(index): Path<u64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(block) = chain.blocks.get(index as usize) {
        (
            StatusCode::OK,
            axum::Json(json!({
                "index": block.index,
                "hash": block.hash,
                "previous_hash": block.previous_hash,
                "timestamp": block.timestamp,
                "signer": block.signer,
                "transactions": block.transactions,
                "documents": block.documents,
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Block nicht gefunden"})),
        )
    }
}

/// POST /sync-users – User-Push empfangen (von anderen Nodes)
async fn sync_receive_users(
    State(state): State<AppState>,
    axum::Json(incoming): axum::Json<Vec<SyncUser>>,
) -> impl IntoResponse {
    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;
    let mut updated = 0usize;

    for inc in &incoming {
        if inc.name.is_empty() {
            continue;
        }
        let existing = users.iter_mut().find(|u| {
            (!u.wallet_address.is_empty() && u.wallet_address == inc.wallet_address)
                || (!inc.id.is_empty() && u.id == inc.id)
        });
        if let Some(ex) = existing {
            if ex.name != inc.name {
                ex.name = inc.name.clone();
                updated += 1;
            }
            if ex.wallet_address.is_empty() && !inc.wallet_address.is_empty() {
                ex.wallet_address = inc.wallet_address.clone();
                updated += 1;
            }
        } else {
            users.push(stone::auth::User {
                id: if inc.id.is_empty() {
                    format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"))
                } else {
                    inc.id.clone()
                },
                name: inc.name.clone(),
                api_key: String::new(),
                phrase_hash: String::new(),
                quota_bytes: stone::auth::default_quota_bytes(),
                wallet_address: inc.wallet_address.clone(),
                account_type: stone::auth::default_account_type(),
                org_id: String::new(),
                org_role: String::new(),
                discord_id: String::new(),
                discord_username: String::new(),
            });
            added += 1;
        }
    }

    if added > 0 || updated > 0 {
        stone::auth::save_users(&users);
        println!("[sync-port] {added} neue + {updated} aktualisierte User empfangen");
    }

    (
        StatusCode::OK,
        axum::Json(json!({"ok": true, "added": added, "updated": updated})),
    )
}

#[derive(Deserialize)]
struct SyncUser {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    wallet_address: String,
}

/// GET /game-economy – Game-Economy-Daten für Peer-Sync
async fn sync_game_economy(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.node.game_economy.read().unwrap_or_else(|e| e.into_inner());
    let json = serde_json::to_value(&*store).unwrap_or(serde_json::json!({}));
    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "game_economy": json,
        })),
    )
}

// ─── Organisation Sync ───────────────────────────────────────────────────────

/// GET /organizations – Organisations-Liste für Peer-Sync
async fn sync_organizations(State(state): State<AppState>) -> impl IntoResponse {
    let orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let sync_list = stone::organization::build_org_sync_list(&orgs);
    (
        StatusCode::OK,
        axum::Json(json!({"ok": true, "organizations": sync_list})),
    )
}

/// POST /sync-organizations – Organisations-Liste von anderen Nodes empfangen und mergen
async fn sync_receive_organizations(
    State(state): State<AppState>,
    axum::Json(incoming): axum::Json<stone::organization::OrgSyncList>,
) -> impl IntoResponse {
    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;
    let mut updated = 0usize;

    for inc in &incoming.organizations {
        if inc.chain_hash.is_empty() {
            continue;
        }

        // Verifiziere den Proof-Hash on-the-fly
        let reconstructed = {
            let mut h = sha2::Sha256::new();
            use sha2::Digest;
            h.update(inc.id.as_bytes());
            h.update(inc.name.as_bytes());
            h.update(inc.owner_id.as_bytes());
            h.update(&inc.created_at.to_le_bytes());
            hex::encode(h.finalize())
        };
        if reconstructed != inc.chain_hash {
            continue; // Proof ungültig – überspringe
        }

        if let Some(existing) = orgs.iter_mut().find(|o| o.id == inc.id) {
            if existing.chain_block_index < inc.chain_block_index {
                existing.chain_hash = inc.chain_hash.clone();
                existing.chain_block_index = inc.chain_block_index;
                existing.chain_block_hash = inc.chain_block_hash.clone();
                updated += 1;
            }
        } else {
            // Neue Organisation anlegen (nur Metadaten)
            let mut org = stone::organization::Organization::create(
                &inc.name,
                &inc.description,
                &inc.owner_id,
                "synced-user",
            );
            org.id = inc.id.clone();
            org.chain_hash = inc.chain_hash.clone();
            org.chain_block_index = inc.chain_block_index;
            org.chain_block_hash = inc.chain_block_hash.clone();
            org.created_at = inc.created_at;
            orgs.push(org);
            added += 1;
        }
    }

    if added > 0 || updated > 0 {
        stone::organization::save_orgs(&orgs);
        println!(
            "[sync-port] {added} neue + {updated} aktualisierte Organisationen empfangen"
        );
    }

    (
        StatusCode::OK,
        axum::Json(json!({"ok": true, "added": added, "updated": updated})),
    )
}

/// GET /chunk/{hash} – Chunk-Daten für Peer-Sync
async fn sync_chunk(
    Path(hash): Path<String>,
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let store = match stone::storage::ChunkStore::new() {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "ChunkStore nicht verfügbar"})),
            )
                .into_response();
        }
    };

    match store.read_chunk(&hash) {
        Ok(data) => {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("content-type", "application/octet-stream".parse().unwrap());
            (StatusCode::OK, headers, data).into_response()
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Chunk nicht gefunden"})),
        )
            .into_response(),
    }
}

// ─── Router bauen ─────────────────────────────────────────────────────────────

pub fn build_sync_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(Any);

    Router::new()
        .route("/health", get(sync_health))
        .route("/info", get(sync_info))
        .route("/users", get(sync_users_list))
        .route("/resolve/{identifier}", get(sync_resolve))
        .route("/peers", get(sync_peers))
        .route("/chain-info", get(sync_chain_info))
        .route("/blocks", get(sync_blocks))
        .route("/blocks/{index}", get(sync_block))
        .route("/sync-users", post(sync_receive_users))
        .route("/organizations", get(sync_organizations))
        .route("/sync-organizations", post(sync_receive_organizations))
        .route("/game-economy", get(sync_game_economy))
        .route("/chunk/{hash}", get(sync_chunk))
        .layer(cors)
        .with_state(state)
}