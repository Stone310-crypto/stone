//! P2P network handlers.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use stone::consensus::{
    BlockProposal, VoteMessage, load_or_create_validator_key,
};

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

/// GET /api/v1/p2p/peers (öffentlich)
pub async fn handle_p2p_peers(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let peers = match &state.network {
        Some(h) => h.get_peers().await,
        None => vec![],
    };
    axum::Json(json!({ "peers": peers, "count": peers.len() }))
}

/// POST /api/v1/p2p/dial
pub async fn handle_p2p_dial(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let addr_str = body["addr"].as_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Feld 'addr' fehlt"})),
        )
            .into_response()
    })?;

    let addr = stone::network::parse_multiaddr(addr_str).map_err(|e| {
        (StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response()
    })?;

    match &state.network {
        Some(h) => {
            h.dial(addr).await;
            Ok(axum::Json(json!({ "ok": true, "addr": addr_str })))
        }
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P nicht aktiv"})),
        )
            .into_response()),
    }
}

/// GET /api/v1/p2p/info (öffentlich)
pub async fn handle_p2p_info(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let p2p_port: u16 = std::env::var("STONE_P2P_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(stone::network::DEFAULT_P2P_PORT);

    let (peer_id, local_addr) = match &state.network {
        Some(h) => (
            h.local_peer_id.clone(),
            stone::network::local_p2p_addr(p2p_port),
        ),
        None => (String::from("P2P deaktiviert"), None),
    };

    let listen_addrs: Vec<String> = match &state.network {
        Some(_) => {
            vec![local_addr.clone().unwrap_or_default()]
        }
        None => vec![],
    };

    axum::Json(json!({
        "peer_id":          peer_id,
        "p2p_addr":         local_addr,
        "p2p_port":         p2p_port,
        "p2p_active":       state.network.is_some(),
        "listen_addrs":     listen_addrs,
    }))
}

/// GET /api/v1/p2p/config (öffentlich)
pub async fn handle_p2p_config(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let config = stone::network::P2pConfig::load_or_default();
    axum::Json(config)
}

/// GET /api/v1/p2p/status
pub async fn handle_p2p_status(State(state): State<AppState>) -> impl IntoResponse {
    let Some(net) = &state.network else {
        return axum::Json(json!({
            "p2p": "disabled",
            "connected_peers": 0,
            "total_known_peers": 0,
            "peers": []
        }))
        .into_response();
    };
    match net.get_status().await {
        Some(s) => axum::Json(json!({
            "local_peer_id":       s.local_peer_id,
            "connected_peers":     s.connected_peers,
            "total_known_peers":   s.total_known_peers,
            "gossipsub_mesh_size": s.gossipsub_mesh_size,
            "chain_block_count":   s.chain_block_count,
            "peers": s.peers.iter().map(|p| json!({
                "peer_id":         p.peer_id,
                "addresses":       p.addresses,
                "agent":           p.agent_version,
                "connected":       p.connected,
                "last_seen_ago_s": p.last_seen_ago_secs,
                "blocks_received": p.blocks_received,
                "in_mesh":         p.in_gossipsub_mesh,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P-Task antwortet nicht"})),
        )
            .into_response(),
    }
}

/// POST /api/v1/p2p/ping/:peer_id
pub async fn handle_p2p_ping(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Path(peer_id_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let net = state.network.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P nicht aktiv"})),
        )
            .into_response()
    })?;

    let peer_id = peer_id_str.parse::<libp2p::PeerId>().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(
                json!({"error": format!("Ungültige PeerId: {peer_id_str}")}),
            ),
        )
            .into_response()
    })?;

    let result = net.ping(peer_id).await;
    let status = if result.reachable {
        StatusCode::OK
    } else {
        StatusCode::REQUEST_TIMEOUT
    };
    Ok((
        status,
        axum::Json(json!({
            "peer_id":    result.peer_id,
            "reachable":  result.reachable,
            "latency_ms": result.latency_ms,
            "error":      result.error,
        })),
    ))
}

/// POST /api/v1/p2p/proposal
///
/// Empfängt einen Block-Proposal von einem Peer-Validator.
/// Validiert den Proposal und gibt eine signierte VoteMessage zurück.
pub async fn handle_p2p_proposal(
    State(state): State<AppState>,
    axum::Json(proposal): axum::Json<BlockProposal>,
) -> impl IntoResponse {
    // 1. Validator-Set laden
    let vs = state.node.validator_set.read().unwrap().clone();

    // 2. Proposer-Signatur prüfen
    if !proposal.verify_proposer(&vs) {
        let signing_key = load_or_create_validator_key();
        let vote = VoteMessage::new(
            proposal.round,
            proposal.block.hash.clone(),
            state.node.node_id.clone(),
            false,
            &signing_key,
            "Ungültige Proposer-Signatur".into(),
        );
        return (StatusCode::OK, axum::Json(json!({
            "ok": false,
            "error": "Ungültige Proposer-Signatur",
            "vote": vote,
        })));
    }

    // 3. Prüfen ob der Proposer der ausgewählte Validator für diesen Slot ist
    let (prev_hash, expected_index) = {
        let chain = state.node.chain.lock().unwrap();
        let ph = chain.blocks.last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        let idx = chain.blocks.len() as u64;
        (ph, idx)
    };

    // Block-Index muss zum lokalen Chain-Stand passen
    if proposal.block.index != expected_index {
        let signing_key = load_or_create_validator_key();
        let vote = VoteMessage::new(
            proposal.round,
            proposal.block.hash.clone(),
            state.node.node_id.clone(),
            false,
            &signing_key,
            format!("Block-Index {} erwartet, {} empfangen", expected_index, proposal.block.index),
        );
        return (StatusCode::OK, axum::Json(json!({
            "ok": false,
            "error": format!("Block-Index Mismatch: erwartet {}, empfangen {}", expected_index, proposal.block.index),
            "vote": vote,
        })));
    }

    // previous_hash muss mit letztem lokalen Block übereinstimmen
    if proposal.block.previous_hash != prev_hash {
        let signing_key = load_or_create_validator_key();
        let vote = VoteMessage::new(
            proposal.round,
            proposal.block.hash.clone(),
            state.node.node_id.clone(),
            false,
            &signing_key,
            "previous_hash stimmt nicht mit lokaler Chain überein".into(),
        );
        return (StatusCode::OK, axum::Json(json!({
            "ok": false,
            "error": "previous_hash Mismatch",
            "vote": vote,
        })));
    }

    // Validator-Auswahl prüfen (SHA256-Rotation)
    if !vs.is_selected_validator(&proposal.proposer_id, &prev_hash, proposal.block.index) {
        let signing_key = load_or_create_validator_key();
        let vote = VoteMessage::new(
            proposal.round,
            proposal.block.hash.clone(),
            state.node.node_id.clone(),
            false,
            &signing_key,
            format!("Validator '{}' ist nicht der ausgewählte für Block #{}", proposal.proposer_id, proposal.block.index),
        );
        return (StatusCode::OK, axum::Json(json!({
            "ok": false,
            "error": "Nicht der ausgewählte Validator für diesen Slot",
            "vote": vote,
        })));
    }

    // 4. Block-Hash verifizieren (Integrität)
    let recalculated = stone::blockchain::calculate_hash(&proposal.block);
    if recalculated != proposal.block.hash {
        let signing_key = load_or_create_validator_key();
        let vote = VoteMessage::new(
            proposal.round,
            proposal.block.hash.clone(),
            state.node.node_id.clone(),
            false,
            &signing_key,
            "Block-Hash stimmt nicht mit Inhalt überein".into(),
        );
        return (StatusCode::OK, axum::Json(json!({
            "ok": false,
            "error": "Block-Hash Integritätsfehler",
            "vote": vote,
        })));
    }

    // 5. Alles OK → Accept-Vote erstellen
    let signing_key = load_or_create_validator_key();
    let vote = VoteMessage::new(
        proposal.round,
        proposal.block.hash.clone(),
        state.node.node_id.clone(),
        true,
        &signing_key,
        String::new(),
    );

    println!(
        "[consensus] 🗳️  Vote für Block #{} von '{}': ✅ Accept",
        proposal.block.index, proposal.proposer_id,
    );

    // 6. Auto-Registrierung: Proposer als Validator hinzufügen falls unbekannt
    {
        let mut vs_w = state.node.validator_set.write().unwrap();
        if vs_w.get(&proposal.proposer_id).is_none() {
            let pub_key_hex = proposal.block.validator_pub_key.clone();
            let mut vi = stone::consensus::ValidatorInfo::new(
                proposal.proposer_id.clone(),
                pub_key_hex,
            );
            vi.name = format!("Auto-discovered (Block #{})", proposal.block.index);
            vi.active = true;
            vs_w.add(vi);
            println!(
                "[consensus] 🔗 Peer '{}' automatisch als Validator registriert",
                proposal.proposer_id,
            );
        }
    }

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "vote": vote,
    })))
}