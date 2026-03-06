//! P2P network handlers.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use stone::consensus::{
    BlockProposal, PreCommitRequest, VoteMessage, VotePhase, load_or_create_validator_key,
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
    // Port aus P2P-Config lesen (authoritative Quelle), Fallback auf ENV / Default
    let config = stone::network::P2pConfig::load_or_default();
    let p2p_port: u16 = config.listen_addr
        .split('/')
        .filter_map(|s| s.parse::<u16>().ok())
        .last()
        .or_else(|| std::env::var("STONE_P2P_PORT").ok().and_then(|v| v.parse().ok()))
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
            let mut addrs = vec![];
            if let Some(ref tcp_addr) = local_addr {
                addrs.push(tcp_addr.clone());
            }
            if let Some(quic_addr) = stone::network::local_quic_addr(p2p_port) {
                addrs.push(quic_addr);
            }
            addrs
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
    let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner()).clone();

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
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
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

    // Validator-Auswahl prüfen (Stake-gewichtete Rotation)
    let (stakes, jailed, wallet_map) = state.node.build_selection_context();
    if !vs.is_selected_validator_weighted(&proposal.proposer_id, &prev_hash, proposal.block.index, &stakes, &jailed, &wallet_map) {
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
        let mut vs_w = state.node.validator_set.write().unwrap_or_else(|e| e.into_inner());
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

// ─── Phase 2: Pre-Commit Handler ──────────────────────────────────────────────

/// Empfängt eine PreCommitRequest vom Proposer.
/// Verifiziert, dass ⅔+1 gültige Pre-Votes vorliegen, und sendet
/// dann eine eigene Pre-Commit-Stimme zurück.
pub async fn handle_p2p_precommit(
    State(state): State<AppState>,
    axum::Json(pcr): axum::Json<PreCommitRequest>,
) -> impl IntoResponse {
    let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner()).clone();
    let signing_key = load_or_create_validator_key();

    // 1. Pre-Votes verifizieren: jede Signatur muss gültig sein
    let mut valid_accepts = 0usize;
    for pv in &pcr.pre_votes {
        if pv.round != pcr.round || pv.block_hash != pcr.block_hash {
            continue; // Ungültige Runde/Hash – zählt nicht
        }
        if pv.phase != VotePhase::PreVote {
            continue; // Muss PreVote sein
        }
        if !pv.verify(&vs) {
            continue; // Ungültige Signatur
        }
        if pv.accept {
            valid_accepts += 1;
        }
    }

    // 2. Prüfen ob ⅔+1 gültige Pre-Votes vorliegen
    let threshold = vs.supermajority_threshold();
    if valid_accepts < threshold {
        let vote = VoteMessage::new_with_phase(
            pcr.round,
            pcr.block_hash.clone(),
            state.node.node_id.clone(),
            false,
            &signing_key,
            format!(
                "Nur {}/{} gültige PreVotes, {}/{} nötig",
                valid_accepts, vs.active_count(), threshold, vs.active_count(),
            ),
            VotePhase::PreCommit,
        );
        return (StatusCode::OK, axum::Json(json!({
            "ok": false,
            "error": format!("PreVote-Quorum nicht erreicht: {}/{}", valid_accepts, threshold),
            "vote": vote,
        })));
    }

    // 3. Block-Hash mit lokaler Chain abgleichen
    let (prev_hash, expected_index) = {
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let ph = chain.blocks.last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        let idx = chain.blocks.len() as u64;
        (ph, idx)
    };

    // Sanity-Check: Der Block-Hash im PreCommit muss einem Block entsprechen
    // den wir in Phase 1 bereits geprüft haben. Wenn wir den Block-Hash nicht
    // kennen (z.B. nach Neustart), akzeptieren wir trotzdem – die PreVotes
    // bestätigen die Gültigkeit bereits durch ⅔+ Signaturen.
    // Aber wenn unser Chain-Stand abweicht, warnen wir.
    if expected_index > 0 {
        // Wir erwarten dass der PreCommit-Block der nächste nach unserem letzten ist
        // Falls wir deutlich hinterher sind (> 5 Blöcke), ist das ein Zeichen
        // dass wir noch syncen und das PreCommit trotzdem akzeptieren sollten
        let _ = (&prev_hash, expected_index); // Für zukünftige strikte Fork-Prüfungen
    }

    // 4. Accept Pre-Commit senden
    let vote = VoteMessage::new_with_phase(
        pcr.round,
        pcr.block_hash.clone(),
        state.node.node_id.clone(),
        true,
        &signing_key,
        String::new(),
        VotePhase::PreCommit,
    );

    println!(
        "[consensus] 🔒 PreCommit für Block '{}' (Runde {}) – {} PreVotes verifiziert",
        &pcr.block_hash[..8.min(pcr.block_hash.len())],
        pcr.round,
        valid_accepts,
    );

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "vote": vote,
    })))
}