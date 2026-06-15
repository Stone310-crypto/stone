//! PoA validators, consensus voting, and fork detection handlers.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::{
    consensus::{
        detect_forks, load_or_create_validator_key, local_validator_pubkey_hex, resolve_fork,
        Checkpoint, ForkCandidate, ValidatorInfo, VoteMessage, CHECKPOINT_INTERVAL,
        SLASH_DOUBLE_SIGN_PERCENT, SLASH_DOWNTIME_PERCENT, SLASH_INVALID_BLOCK_PERCENT,
        DOWNTIME_THRESHOLD_BLOCKS, SLASH_JAIL_DURATION_SECS,
    },
    master::NodeEvent,
};

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

fn validator_mutations_enabled() -> bool {
    matches!(
        std::env::var("STONE_ENABLE_VALIDATORSET_MUTATIONS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn validator_mutation_lock_response() -> Response {
    (
        StatusCode::LOCKED,
        axum::Json(json!({
            "error": "ValidatorSet-Mutationen sind gesperrt (P0.5 Governance-Lock aktiv)",
            "hint": "Setze STONE_ENABLE_VALIDATORSET_MUTATIONS=1 nur fuer kontrollierte Wartungsfenster",
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct AddValidatorRequest {
    pub node_id: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Deserialize)]
pub struct CastVoteRequest {
    pub round: u64,
    pub block_hash: String,
    pub accept: bool,
    #[serde(default)]
    pub reason: String,
}

/// GET /api/v1/validators (öffentlich)
pub async fn handle_list_validators(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
    (
        StatusCode::OK,
        axum::Json(json!({
            "validators": vs.validators,
            "active_count": vs.active_count(),
            "supermajority_threshold": vs.supermajority_threshold(),
            "poa_active": !vs.validators.is_empty(),
        })),
    )
}

/// POST /api/v1/validators
pub async fn handle_add_validator(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AddValidatorRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if !validator_mutations_enabled() {
        return Err(validator_mutation_lock_response());
    }

    if req.node_id.trim().is_empty() || req.public_key_hex.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(
                json!({"error": "node_id und public_key_hex sind erforderlich"}),
            ),
        )
            .into_response());
    }

    if req.public_key_hex.len() != 64 || hex::decode(&req.public_key_hex).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "public_key_hex muss ein 64-Zeichen-Hex-String (32 Byte) sein"})),
        )
            .into_response());
    }

    let mut info = ValidatorInfo::new(&req.node_id, &req.public_key_hex);
    info.name = req.name.clone();
    info.endpoint = req.endpoint.clone();

    let node_id = info.node_id.clone();
    {
        let mut vs = state.node.validator_set.write().unwrap_or_else(|e| e.into_inner());
        vs.add(info);
    }

    state.node.events.publish(NodeEvent::ValidatorAdded {
        node_id: node_id.clone(),
        pub_key_hex: req.public_key_hex.clone(),
        name: req.name.clone(),
    });

    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "message": format!("Validator {} hinzugefügt", node_id),
            "node_id": node_id,
            "public_key_hex": req.public_key_hex,
        })),
    ))
}

/// DELETE /api/v1/validators/:node_id
pub async fn handle_remove_validator(
    headers: HeaderMap,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if !validator_mutations_enabled() {
        return Err(validator_mutation_lock_response());
    }

    let removed = {
        let mut vs = state.node.validator_set.write().unwrap_or_else(|e| e.into_inner());
        vs.remove(&node_id)
    };

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": format!("Validator '{}' nicht gefunden", node_id)})),
        )
            .into_response());
    }

    state.node.events.publish(NodeEvent::ValidatorRemoved {
        node_id: node_id.clone(),
    });

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "message": format!("Validator {} entfernt", node_id),
            "node_id": node_id,
        })),
    ))
}

/// PATCH /api/v1/validators/:node_id/activate
pub async fn handle_set_validator_active(
    headers: HeaderMap,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if !validator_mutations_enabled() {
        return Err(validator_mutation_lock_response());
    }

    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);

    let ok = {
        let mut vs = state.node.validator_set.write().unwrap_or_else(|e| e.into_inner());
        vs.set_active(&node_id, active)
    };

    if !ok {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": format!("Validator '{}' nicht gefunden", node_id)})),
        )
            .into_response());
    }

    state
        .node
        .events
        .publish(NodeEvent::ValidatorStatusChanged {
            node_id: node_id.clone(),
            active,
        });

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "node_id": node_id,
            "active": active,
        })),
    ))
}

/// GET /api/v1/validators/self
pub async fn handle_validator_self(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let sk = load_or_create_validator_key();
    let pk = local_validator_pubkey_hex(&sk);
    (
        StatusCode::OK,
        axum::Json(json!({
            "public_key_hex": pk,
            "note": "Diesen Public Key verwenden um diese Node als Validator zu registrieren",
        })),
    )
}

/// GET /api/v1/consensus/status (öffentlich)
pub async fn handle_consensus_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
    let voting = state.node.active_voting.lock().unwrap_or_else(|e| e.into_inner());

    let status = if let Some(ref round) = *voting {
        let tally = round.tally(&vs);
        json!({
            "active": true,
            "round": round.round,
            "block_hash": round.block_hash,
            "proposer_id": round.proposer_id,
            "started_at": round.started_at,
            "finalized": round.finalized,
            "accepted": round.accepted,
            "tally": tally,
            "votes": round.votes.values().collect::<Vec<_>>(),
        })
    } else {
        json!({ "active": false })
    };
    drop(voting);
    drop(vs);

    // Nächste Validator-Auswahl mit Stake-Gewichtung
    let (stakes, jailed, wallet_map) = state.node.build_selection_context();
    let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());

    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let next_index = chain.blocks.len() as u64;
    let prev_hash = chain.blocks.last()
        .map(|b| b.hash.clone())
        .unwrap_or_else(|| "genesis".into());
    drop(chain);

    let next_validator = vs.select_validator_weighted(&prev_hash, next_index, &stakes, &jailed, &wallet_map)
        .map(|v| v.node_id.clone());

    // Gewichte für alle Validatoren berechnen
    let base_weight = rust_decimal::Decimal::ONE;
    let validator_weights: Vec<serde_json::Value> = vs.validators.iter()
        .filter(|v| v.active)
        .map(|v| {
            let wallet = wallet_map.get(&v.node_id);
            let stake = wallet
                .and_then(|w| stakes.get(w))
                .copied()
                .unwrap_or(rust_decimal::Decimal::ZERO);
            let is_jailed = jailed.contains(&v.node_id);
            let total_weight = if is_jailed {
                rust_decimal::Decimal::ZERO
            } else {
                stake + base_weight
            };
            json!({
                "node_id": v.node_id,
                "stake": stake.to_string(),
                "base_weight": "1",
                "total_weight": total_weight.to_string(),
                "jailed": is_jailed,
                "is_next": next_validator.as_deref() == Some(&v.node_id),
            })
        })
        .collect();

    (StatusCode::OK, axum::Json(json!({
        "voting": status,
        "next_block_index": next_index,
        "next_validator": next_validator,
        "validator_weights": validator_weights,
        "selection_mode": "stake-weighted",
    })))
}

/// POST /api/v1/consensus/vote
pub async fn handle_cast_vote(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<CastVoteRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let sk = load_or_create_validator_key();
    let pk_hex = local_validator_pubkey_hex(&sk);

    let voter_id = {
        let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
        if !vs.validators.is_empty() {
            let Some(v) = vs
                .validators
                .iter()
                .find(|v| v.public_key_hex == pk_hex)
            else {
                return Err((
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({
                        "error": "Lokaler Validator-Key ist nicht im ValidatorSet registriert",
                    })),
                )
                    .into_response());
            };
            if !v.active {
                return Err((
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({
                        "error": format!(
                            "Validator '{}' ist inaktiv und darf nicht voten",
                            v.node_id
                        ),
                    })),
                )
                    .into_response());
            }
            v.node_id.clone()
        } else {
            vs.validators
            .iter()
            .find(|v| v.public_key_hex == pk_hex)
            .map(|v| v.node_id.clone())
            .unwrap_or_else(|| state.node.node_id.clone())
        }
    };

    let vote = VoteMessage::new(
        req.round,
        req.block_hash.clone(),
        voter_id.clone(),
        req.accept,
        &sk,
        req.reason.clone(),
    );

    let tally = {
        let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
        let mut voting = state.node.active_voting.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(ref mut round) = *voting {
            round.add_vote(vote, &vs).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": e})),
                )
                    .into_response()
            })?;
            Some(round.tally(&vs))
        } else {
            return Err((
                StatusCode::CONFLICT,
                axum::Json(json!({"error": "Keine aktive Voting-Runde"})),
            )
                .into_response());
        }
    };

    if let Some(t) = &tally {
        state.node.events.publish(NodeEvent::VoteReceived {
            round: req.round,
            block_hash: req.block_hash.clone(),
            voter_id: voter_id.clone(),
            accept: req.accept,
            accepts: t.accepts,
            needed: t.threshold,
        });
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "vote_recorded": true,
            "voter_id": voter_id,
            "tally": tally,
        })),
    ))
}

/// GET /api/v1/forks (öffentlich)
pub async fn handle_detect_forks(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());

    let mut fork_groups = detect_forks(&chain.blocks);

    for group in &mut fork_groups {
        for candidate in group.iter_mut() {
            let result = vs.verify_block(
                &candidate.block_hash,
                &candidate.signer_id,
                &candidate.validator_signature,
            );
            candidate.signature_valid = result.is_acceptable();
        }
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "forks_detected": fork_groups.len(),
            "fork_groups": fork_groups,
        })),
    )
}

/// POST /api/v1/forks/resolve
pub async fn handle_resolve_fork(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let candidates: Vec<ForkCandidate> = serde_json::from_value(
        body.get("candidates").cloned().unwrap_or(json!([])),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": format!("Ungültige Kandidaten: {e}")})),
        )
            .into_response()
    })?;

    if candidates.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Keine Kandidaten angegeben"})),
        )
            .into_response());
    }

    let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
    let resolution = resolve_fork(candidates, &vs);

    match resolution {
        Some(res) => {
            state.node.events.publish(NodeEvent::ForkResolved {
                winning_hash: res.winning_hash.clone(),
                dropped_blocks: 0,
                reason: format!("{:?}", res.reason),
            });
            Ok((
                StatusCode::OK,
                axum::Json(json!({
                    "winning_hash": res.winning_hash,
                    "reason": format!("{:?}", res.reason),
                    "candidates": res.candidates,
                })),
            ))
        }
        None => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "Fork-Auflösung fehlgeschlagen"})),
        )
            .into_response()),
    }
}

// ─── Checkpoint / Finality Endpoints ─────────────────────────────────────────

/// GET /api/v1/checkpoints — Alle Checkpoints abrufen (öffentlich)
pub async fn handle_list_checkpoints(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let store = state.node.checkpoint_store.read().unwrap_or_else(|e| e.into_inner());
    let latest_finalized = store.latest_finalized().map(|c| c.block_index);
    (
        StatusCode::OK,
        axum::Json(json!({
            "checkpoints": store.checkpoints,
            "total": store.checkpoints.len(),
            "finalized": store.finalized_count(),
            "latest_finalized_block": latest_finalized,
            "checkpoint_interval": CHECKPOINT_INTERVAL,
        })),
    )
}

/// POST /api/v1/checkpoint — Checkpoint von Peer empfangen und Signatur mergen
pub async fn handle_receive_checkpoint(
    State(state): State<AppState>,
    axum::Json(incoming): axum::Json<Checkpoint>,
) -> impl IntoResponse {
    // Validierung: Block-Hash muss mit unserer Chain übereinstimmen
    let local_hash = {
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let idx = incoming.block_index as usize;
        if idx < chain.blocks.len() {
            Some(chain.blocks[idx].hash.clone())
        } else {
            None
        }
    };

    match local_hash {
        Some(hash) if hash == incoming.block_hash => {
            // ── Phase 1.5: Validator-Mitzeichnen + Re-Broadcast ──────────────
            // Wenn ich selbst noch nicht für diesen Checkpoint signiert habe,
            // signiere lokal nach und propagiere den ergänzten Checkpoint weiter.
            // So sammeln sich Validator-Signaturen organisch über das Netzwerk.
            let node_id = state.node.node_id.clone();
            let already_signed_by_me = incoming.signatures.contains_key(&node_id);

            let mut merged = incoming.clone();
            if !already_signed_by_me {
                let sk = load_or_create_validator_key();
                merged.sign(&node_id, &sk);
            }

            // Signaturen mergen
            let (was_finalized_before, sigs_grew) = {
                let mut store = state.node.checkpoint_store.write().unwrap_or_else(|e| e.into_inner());
                let before_finalized = store.latest_finalized().map(|c| c.block_index);
                let before_sig_count = store
                    .get(merged.block_index)
                    .map(|c| c.signatures.len())
                    .unwrap_or(0);
                store.add_or_update(merged.clone());
                let after_sig_count = store
                    .get(merged.block_index)
                    .map(|c| c.signatures.len())
                    .unwrap_or(0);
                (before_finalized, after_sig_count > before_sig_count)
            };

            let is_now_finalized = {
                let store = state.node.checkpoint_store.read().unwrap_or_else(|e| e.into_inner());
                store.latest_finalized().map(|c| c.block_index)
            };

            let newly_finalized = is_now_finalized != was_finalized_before
                && is_now_finalized == Some(incoming.block_index);

            if newly_finalized {
                println!(
                    "[checkpoint] ✅ Block #{} durch Peer-Signaturen finalisiert!",
                    incoming.block_index
                );
            }

            // Re-Broadcast: nur wenn neue Signaturen dazukamen (verhindert Storm)
            // und der Checkpoint noch nicht finalisiert ist.
            let should_rebroadcast = sigs_grew && !merged.is_finalized();
            if should_rebroadcast {
                let peer_urls: Vec<String> = {
                    let peers = state.node.peers.read().unwrap_or_else(|e| e.into_inner());
                    peers.iter()
                        .filter(|p| p.is_healthy())
                        .map(|p| p.url.clone())
                        .collect()
                };
                if !peer_urls.is_empty() {
                    let cp_json = serde_json::to_vec(&merged).unwrap_or_default();
                    tokio::spawn(async move {
                        let client = match reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(5))
                            .danger_accept_invalid_certs(true)
                            .build()
                        {
                            Ok(c) => c,
                            Err(_) => return,
                        };
                        for peer in &peer_urls {
                            let url = format!("{}/api/v1/checkpoint", peer.trim_end_matches('/'));
                            let _ = client
                                .post(&url)
                                .header("Content-Type", "application/json")
                                .body(cp_json.clone())
                                .send()
                                .await;
                        }
                    });
                }
            }

            (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "block_index": incoming.block_index,
                    "finalized": newly_finalized,
                    "signed_locally": !already_signed_by_me,
                    "rebroadcast": should_rebroadcast,
                })),
            )
        }
        Some(hash) => {
            (
                StatusCode::CONFLICT,
                axum::Json(json!({
                    "error": format!(
                        "Block-Hash Mismatch: lokal={} vs. checkpoint={}",
                        hash, incoming.block_hash
                    ),
                })),
            )
        }
        None => {
            // Block noch nicht vorhanden – speichern wir trotzdem (Peer könnte weiter sein)
            let mut store = state.node.checkpoint_store.write().unwrap_or_else(|e| e.into_inner());
            store.add_or_update(incoming.clone());
            (
                StatusCode::ACCEPTED,
                axum::Json(json!({
                    "ok": true,
                    "note": "Block noch nicht lokal vorhanden, Checkpoint gespeichert",
                    "block_index": incoming.block_index,
                })),
            )
        }
    }
}

// ─── Slashing Endpoints ─────────────────────────────────────────────────────────────

/// GET /api/v1/slashing — Alle Slashing-Records und Jail-Status (öffentlich)
pub async fn handle_slashing_info(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let store = state.node.slashing_store.read().unwrap_or_else(|e| e.into_inner());
    let jailed_validators: Vec<_> = store.jailed.iter()
        .map(|(id, until)| json!({
            "validator_id": id,
            "jail_until": until,
            "remaining_secs": (*until - chrono::Utc::now().timestamp()).max(0),
        }))
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "records": store.records,
            "total_slashing_events": store.records.len(),
            "jailed_validators": jailed_validators,
            "jailed_count": store.jailed.len(),
            "config": {
                "double_sign_penalty_percent": SLASH_DOUBLE_SIGN_PERCENT,
                "downtime_penalty_percent": SLASH_DOWNTIME_PERCENT,
                "invalid_block_penalty_percent": SLASH_INVALID_BLOCK_PERCENT,
                "downtime_threshold_blocks": DOWNTIME_THRESHOLD_BLOCKS,
                "jail_duration_secs": SLASH_JAIL_DURATION_SECS,
            },
        })),
    )
}

/// GET /api/v1/slashing/:validator_id — Slashing-Info für einen bestimmten Validator
pub async fn handle_slashing_validator(
    State(state): State<AppState>,
    Path(validator_id): Path<String>,
) -> impl IntoResponse {
    let store = state.node.slashing_store.read().unwrap_or_else(|e| e.into_inner());
    let records: Vec<_> = store.records.iter()
        .filter(|r| r.validator_id == validator_id)
        .collect();
    let is_jailed = store.is_jailed(&validator_id);
    let jail_until = store.jailed.get(&validator_id).copied();
    let total_slashed = store.total_slashed(&validator_id);

    (
        StatusCode::OK,
        axum::Json(json!({
            "validator_id": validator_id,
            "records": records,
            "offense_count": records.len(),
            "total_slashed": total_slashed.to_string(),
            "is_jailed": is_jailed,
            "jail_until": jail_until,
        })),
    )
}
