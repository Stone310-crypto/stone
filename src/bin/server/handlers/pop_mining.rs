//! Proof-of-Play Mining Handler
//!
//! GET  /api/v1/sdk/mining/challenge      – current slot challenge
//! POST /api/v1/sdk/mining/submit         – submit a block-find proof → earn STONE
//! GET  /api/v1/sdk/mining/stats          – server-wide PoP mining statistics
//! POST /api/v1/sdk/mining/register-hash  – approve a plugin hash for PoP eligibility

use axum::{Json, extract::State, http::HeaderMap};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::json;
use stone::{
    pop_mining::{PopProof, current_slot_id, slot_expires_at, POP_BLOCK_REWARD, SLOT_DURATION_SECS},
    token::{TxType, Wallet},
};

use super::super::state::AppState;
use super::game::validate_sdk_key_for_watchdog;

// ── GET /api/v1/sdk/mining/challenge ─────────────────────────────────────────

pub async fn handle_pop_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let game_id = match validate_sdk_key_for_watchdog(&state, &headers) {
        Ok(id) => id,
        Err(e) => return Json(json!({ "ok": false, "error": e })),
    };

    let chain_tip_hash = current_chain_tip(&state);
    let slot_id = current_slot_id();
    let expires_at = slot_expires_at(slot_id);
    let (difficulty_target, min_activity_events) = state.pop_mining.current_params();

    eprintln!(
        "[pop-mining] challenge game={game_id} slot={slot_id} tip={}...",
        &chain_tip_hash[..chain_tip_hash.len().min(16)]
    );

    Json(json!({
        "ok": true,
        "game_id": game_id,
        "chain_tip_hash": chain_tip_hash,
        "slot_id": slot_id,
        "slot_expires_at": expires_at,
        "slot_duration_secs": SLOT_DURATION_SECS,
        "difficulty_target": difficulty_target,
        "min_activity_events": min_activity_events,
        "reward_stone": POP_BLOCK_REWARD,
    }))
}

// ── POST /api/v1/sdk/mining/submit ────────────────────────────────────────────

pub async fn handle_pop_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(proof): Json<PopProof>,
) -> Json<serde_json::Value> {
    let game_id = match validate_sdk_key_for_watchdog(&state, &headers) {
        Ok(id) => id,
        Err(e) => return Json(json!({ "ok": false, "error": e })),
    };

    if proof.game_id != game_id {
        return Json(json!({ "ok": false, "error": "game_id stimmt nicht mit SDK-Key überein" }));
    }

    let chain_tip = current_chain_tip(&state);
    let result = state.pop_mining.verify_proof(&proof, &chain_tip);

    if !result.ok {
        eprintln!(
            "[pop-mining] ❌ rejected game={} player={} slot={} reason={}",
            game_id,
            proof.player_wallet,
            proof.slot_id,
            result.error.as_deref().unwrap_or("unknown")
        );
        return Json(json!({ "ok": false, "error": result.error }));
    }

    let reward = result.reward_stone.unwrap_or(POP_BLOCK_REWARD);

    // Cap check via play_drops tracker (daily per-player and per-game limits)
    if let Err(e) = state.play_drops.try_consume(&game_id, &proof.player_wallet, reward) {
        return Json(json!({ "ok": false, "error": format!("Tageslimit erreicht: {e}") }));
    }

    // Load gaming pool mnemonic
    let pool_mnemonic = if stone::gaming_pool::is_configured(&game_id) {
        let pass = stone::gaming_pool::resolve_data_passphrase();
        match stone::gaming_pool::load_pool_mnemonic(&game_id, &pass) {
            Ok(m) => m,
            Err(e) => return Json(json!({ "ok": false, "error": format!("Pool-Schlüssel: {e}") })),
        }
    } else {
        match std::env::var("STONE_GAMING_POOL_MNEMONIC") {
            Ok(m) if !m.trim().is_empty() => m,
            _ => return Json(json!({
                "ok": false,
                "error": "Gaming-Pool nicht konfiguriert (STONE_GAMING_POOL_MNEMONIC oder /sdk/owner/gaming-pool/configure)"
            })),
        }
    };

    let pool_wallet = match Wallet::from_mnemonic(pool_mnemonic.trim()) {
        Ok(w) => w,
        Err(e) => return Json(json!({ "ok": false, "error": format!("Pool-Wallet: {e}") })),
    };

    // 90% to player, 10% to foundation (mining rewards vs. 70/20/10 play-drops)
    let reward_dec: Decimal = reward.to_string().parse().unwrap_or(Decimal::ZERO);
    let foundation_pct = (reward_dec * Decimal::new(10, 2)).round_dp(8);
    let player_amount = reward_dec - foundation_pct;
    let foundation_addr = std::env::var("STONE_FOUNDATION_TREASURY_ADDR")
        .unwrap_or_else(|_| "pool:treasury".to_string());

    let base_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&pool_wallet.address())
            + state.node.mempool.sender_pending_count(&pool_wallet.address())
    };

    let memo = format!("pop_mining:{}:{}", proof.game_id, proof.slot_id);
    let mut tx_ids: Vec<String> = Vec::new();

    for (i, (to, amt)) in [(proof.player_wallet.as_str(), player_amount), (&*foundation_addr, foundation_pct)]
        .iter()
        .enumerate()
    {
        if *amt <= Decimal::ZERO {
            continue;
        }
        let tx = match pool_wallet.sign_tx_with_tier(
            TxType::Transfer,
            to.to_string(),
            *amt,
            base_nonce + i as u64,
            format!("{memo}:{}", if i == 0 { "player" } else { "foundation" }),
            stone::token::FeeTier::Standard,
        ) {
            Ok(t) => t,
            Err(e) => return Json(json!({ "ok": false, "error": format!("TX-Sign: {e}") })),
        };

        {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = state.node.mempool.add_tx(tx.clone(), Some(&ledger)) {
                return Json(json!({ "ok": false, "error": format!("Mempool: {e}") }));
            }
        }

        if let Some(ref net) = state.network {
            let net = net.clone();
            let tx2 = tx.clone();
            tokio::spawn(async move { net.broadcast_tx(tx2).await; });
        }

        tx_ids.push(tx.tx_id.clone());
    }

    eprintln!(
        "[pop-mining] ✅ reward game={} player={} stone={} slot={} tx={}",
        game_id,
        proof.player_wallet,
        player_amount,
        proof.slot_id,
        tx_ids.first().map(|s| &s[..s.len().min(16)]).unwrap_or("none")
    );

    Json(json!({
        "ok": true,
        "reward_stone": reward,
        "player_amount": player_amount.to_string(),
        "tx_id": tx_ids.first(),
        "tx_ids": tx_ids,
        "slot_id": proof.slot_id,
    }))
}

// ── GET /api/v1/sdk/mining/stats ──────────────────────────────────────────────

pub async fn handle_pop_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let _game_id = match validate_sdk_key_for_watchdog(&state, &headers) {
        Ok(id) => id,
        Err(e) => return Json(json!({ "ok": false, "error": e })),
    };

    let (total_finds, total_stone) = state.pop_mining.stats();
    let (difficulty, min_events) = state.pop_mining.current_params();
    let slot_id = current_slot_id();

    Json(json!({
        "ok": true,
        "current_slot": slot_id,
        "slot_duration_secs": SLOT_DURATION_SECS,
        "difficulty_target": difficulty,
        "min_activity_events": min_events,
        "reward_per_block": POP_BLOCK_REWARD,
        "total_finds_lifetime": total_finds,
        "total_stone_rewarded_lifetime": total_stone,
    }))
}

// ── POST /api/v1/sdk/mining/activity ─────────────────────────────────────────
//
// The Minecraft plugin calls this whenever players are actively mining (breaking
// blocks). It is throttled to ~1 request per 15 seconds from the plugin side.
//
// Effect on BlockTimer: as long as this endpoint is called within the last
// heartbeat_timeout_secs, the auto-block countdown is suppressed — identical to
// a registered CPU miner sending heartbeats. When no call comes in (players idle
// or offline), the timer resumes and auto-blocks fire after 120 s.

pub async fn handle_pop_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let game_id = match validate_sdk_key_for_watchdog(&state, &headers) {
        Ok(id) => id,
        Err(e) => return Json(json!({ "ok": false, "error": e })),
    };

    state.pop_mining.record_activity(&game_id);

    let hb_timeout = state.node.auto_mining_config.heartbeat_timeout_secs;
    let active_count = state.pop_mining.active_server_count(hb_timeout);

    eprintln!("[pop-mining] activity game={game_id} active_servers={active_count}");

    Json(json!({
        "ok": true,
        "game_id": game_id,
        "active_pop_servers": active_count,
    }))
}

// ── POST /api/v1/sdk/mining/register-hash ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterHashReq {
    pub game_id: String,
    pub plugin_hash: String,
}

pub async fn handle_pop_register_hash(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterHashReq>,
) -> Json<serde_json::Value> {
    let game_id = match validate_sdk_key_for_watchdog(&state, &headers) {
        Ok(id) => id,
        Err(e) => return Json(json!({ "ok": false, "error": e })),
    };

    if req.game_id != game_id {
        return Json(json!({ "ok": false, "error": "game_id stimmt nicht überein" }));
    }
    if req.plugin_hash.len() != 64 {
        return Json(json!({ "ok": false, "error": "plugin_hash muss 64 Hex-Zeichen (SHA-256) sein" }));
    }

    state.pop_mining.register_hash(&game_id, &req.plugin_hash);
    eprintln!("[pop-mining] hash registriert game={game_id} hash={}...", &req.plugin_hash[..16]);

    Json(json!({ "ok": true, "registered": req.plugin_hash }))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn current_chain_tip(state: &AppState) -> String {
    state
        .node
        .chain
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .blocks
        .last()
        .map(|b| b.hash.clone())
        .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string())
}
