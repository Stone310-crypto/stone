//! Mining-Dashboard handlers – Mining-Status, Metriken, Throttle und Reward-Withdrawal.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::Ordering;

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

use stone::consensus::{load_or_create_validator_key, local_validator_pubkey_hex};
use stone::token::transaction::{create_signed_tx, TxType};

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ThrottleRequest {
    /// Mining-Leistung in Prozent (0 = Mining aus, 100 = volle Leistung)
    pub percent: u64,
}

#[derive(Deserialize)]
pub struct WithdrawRequest {
    /// Ziel-Wallet-Adresse (Ed25519 Public Key Hex)
    pub to_wallet: String,
    /// Betrag in STONE (z.B. "5.0")
    pub amount: String,
    /// Optionaler Memo-Text
    #[serde(default)]
    pub memo: String,
}

#[derive(Deserialize)]
pub struct StakeRequest {
    /// Betrag in STONE (z.B. "500")
    pub amount: String,
}

#[derive(Deserialize)]
pub struct UnstakeRequest {
    /// Betrag in STONE (z.B. "200")
    pub amount: String,
}

#[derive(Deserialize)]
pub struct BindWalletRequest {
    /// Wallet-Adresse die an das Mining gebunden werden soll
    /// (muss die Wallet des eingeloggten Users sein)
    pub wallet: String,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// GET /api/v1/mining/status — Mining-Status und Metriken
///
/// Gibt alle Mining-relevanten Metriken zurück:
/// - Blöcke geminet, Rewards, letzte Block-Zeit
/// - Throttle-Einstellung
/// - Chain-Höhe, Mempool, Staking-Infos
pub async fn handle_mining_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let _user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let metrics = state.node.snapshot_metrics();
    let chain_summary = state.node.chain_summary();

    // Mempool-Statistiken
    let pending_count = state.node.mempool.pending_count();

    // Staking-Infos
    let (total_staked, total_staked_dec, staker_count) = {
        let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
        (pool.total_staked.to_string(), pool.total_staked, pool.stakers.len())
    };

    // Token-Supply — `circulating` = total_supply − staked − reward-pool
    let (total_supply, circulating, validator_balance, pool_balance, validator_wallet) = {
        let signing_key = load_or_create_validator_key();
        let vw = local_validator_pubkey_hex(&signing_key);
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let ts = ledger.total_supply();
        let pool_bal = ledger.balance("pool:storage_rewards");
        let circ = ts - total_staked_dec - pool_bal;
        (
            ts.to_string(),
            circ.to_string(),
            ledger.balance(&vw).to_string(),
            pool_bal.to_string(),
            vw,
        )
    };

    // PoA Validator-Status
    let (is_validator, validator_count) = {
        let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
        (
            vs.is_active_validator(&state.node.node_id),
            vs.validators.len(),
        )
    };

    // Rewards in STONE umrechnen (gespeichert als Milli-STONE × 1000)
    let total_rewards_stone = metrics.total_rewards_milli as f64 / 1000.0;

    // Durchschnittliche Block-Zeit berechnen
    let avg_block_time_secs = if metrics.blocks_mined > 1 && metrics.uptime_secs > 0 {
        metrics.uptime_secs as f64 / metrics.blocks_mined as f64
    } else {
        0.0
    };

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "mining": {
                "active": metrics.mining_throttle_pct > 0,
                "throttle_pct": metrics.mining_throttle_pct,
                "blocks_mined": metrics.blocks_mined,
                "total_rewards": format!("{:.4}", total_rewards_stone),
                "total_rewards_raw": total_rewards_stone,
                "last_block_timestamp": metrics.last_block_timestamp,
                "avg_block_time_secs": format!("{:.1}", avg_block_time_secs),
                "chat_messages_mined": metrics.chat_messages_mined,
            },
            "chain": {
                "block_height": chain_summary.block_height,
                "latest_hash": chain_summary.latest_hash,
                "total_documents": chain_summary.total_documents,
                "chain_valid": chain_summary.is_valid,
            },
            "mempool": {
                "pending_txs": pending_count,
            },
            "node": {
                "node_id": state.node.node_id,
                "role": format!("{:?}", state.node.role),
                "uptime_secs": metrics.uptime_secs,
                "is_validator": is_validator,
                "validator_count": validator_count,
                "requests_total": metrics.requests_total,
            },
            "network": {
                "peers_total": metrics.peers_total,
                "peers_healthy": metrics.peers_healthy,
                "sync_runs": metrics.sync_runs,
                "sync_success": metrics.sync_success,
                "sync_failure": metrics.sync_failure,
            },
            "token": {
                "total_supply": total_supply,
                "circulating": circulating,
                "total_staked": total_staked,
                "staker_count": staker_count,
                "validator_wallet": validator_wallet,
                "validator_balance": validator_balance,
                "reward_pool_balance": pool_balance,
            },
        })),
    )
        .into_response()
}

/// POST /api/v1/mining/throttle — Mining-Leistung begrenzen (nur Admin)
///
/// Setzt die Mining-Leistung in Prozent:
/// - 0   = Mining komplett deaktiviert
/// - 50  = ~50% der Blöcke werden geminet
/// - 100 = volle Leistung (Standard)
pub async fn handle_mining_throttle(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<ThrottleRequest>,
) -> impl IntoResponse {
    // Nur Admin darf Mining-Leistung steuern
    if let Err(e) = super::super::auth_middleware::require_admin(&headers, &state) {
        return e.into_response();
    }

    let pct = req.percent.min(100);
    state
        .node
        .metrics
        .mining_throttle_pct
        .store(pct, Ordering::Relaxed);

    let status = if pct == 0 {
        "Mining deaktiviert"
    } else if pct < 100 {
        "Mining gedrosselt"
    } else {
        "Volle Mining-Leistung"
    };

    println!("[mining] ⚡ Throttle geändert: {pct}% – {status}");

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "throttle_pct": pct,
            "status": status,
        })),
    )
        .into_response()
}

/// POST /api/v1/mining/withdraw — Mining-Rewards auf eigene Wallet transferieren
///
/// Nur der User dessen Wallet die gebundene Mining-Wallet ist, darf Rewards abheben.
///
/// Body: `{ "to_wallet": "hex...", "amount": "5.0", "memo": "optional" }`
pub async fn handle_mining_withdraw(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<WithdrawRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // ── Account-Bindung prüfen: Nur der Reward-Wallet-Owner darf withdrawen ──
    let reward_wallet = state.node.effective_reward_wallet();
    if user.wallet_address != reward_wallet {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "ok": false,
                "error": "Nur der Mining-Wallet-Besitzer darf Rewards abheben",
                "your_wallet": user.wallet_address,
                "mining_wallet": reward_wallet,
                "hint": "Binde deine Wallet zuerst mit POST /api/v1/mining/bind-wallet",
            })),
        ).into_response();
    }

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "Ungültiger Betrag",
            })),
        ).into_response(),
    };

    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "Betrag muss positiv sein",
            })),
        ).into_response();
    }

    // Ziel-Wallet validieren (muss gültiger 32-Byte Ed25519 Public Key in Hex sein)
    if req.to_wallet.len() != 64
        || !req.to_wallet.chars().all(|c| c.is_ascii_hexdigit())
    {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "Ungültige Ziel-Wallet-Adresse (muss 64 Hex-Zeichen / 32-Byte Ed25519 Public Key sein)",
            })),
        ).into_response();
    }

    // Validator-Key laden – Withdrawal kommt IMMER aus der Validator-Wallet,
    // weil nur dafür der Signing-Key auf dem Server liegt.
    // Wenn mining_wallet gebunden ist, gehen die Rewards direkt dorthin
    // (kein Withdrawal nötig). Vom Validator-Wallet können Rewards
    // abgehoben werden die VOR der Bindung akkumuliert wurden.
    let signing_key = load_or_create_validator_key();
    let source_wallet = local_validator_pubkey_hex(&signing_key);

    // Balance und Nonce atomar mit Mempool-Pending-State lesen, um Race
    // Conditions bei gleichzeitigen Requests zu vermeiden.
    let (balance, nonce) = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base_nonce = ledger.nonce(&source_wallet);
        let pending_count = state.node.mempool.sender_pending_count(&source_wallet);
        (ledger.balance(&source_wallet), base_nonce + pending_count)
    };

    if balance < amount {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "Nicht genug Balance für diesen Withdrawal",
            })),
        ).into_response();
    }

    // Transfer-TX erstellen und signieren
    let memo = if req.memo.is_empty() {
        "Mining Reward Withdrawal".to_string()
    } else {
        req.memo
    };

    // Minimale Fee auch für Mining-Withdrawals um Spam zu verhindern
    let withdrawal_fee = rust_decimal::Decimal::new(1, 3); // 0.001 STONE

    if balance < amount + withdrawal_fee {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "Nicht genug Balance (inkl. 0.001 STONE Gebühr)",
            })),
        ).into_response();
    }

    let tx = match create_signed_tx(
        &signing_key,
        TxType::Transfer,
        source_wallet.clone(),
        req.to_wallet.clone(),
        amount,
        withdrawal_fee,
        nonce,
        memo,
    ) {
        Ok(tx) => tx,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({
                "ok": false,
                "error": format!("TX-Erstellung fehlgeschlagen: {e}"),
            })),
        ).into_response(),
    };

    let tx_id = tx.tx_id.clone();

    // In Mempool einfügen (mit Ledger-Pre-Check)
    let submit_result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx, Some(&ledger))
    };

    match submit_result {
        Ok(_) => {
            println!(
                "[mining] 💸 Withdrawal: {} STONE → {} (TX: {}…)",
                amount,
                &req.to_wallet[..16.min(req.to_wallet.len())],
                &tx_id[..12]
            );

            (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "tx_id": tx_id,
                    "from": source_wallet,
                    "to": req.to_wallet,
                    "amount": amount.to_string(),
                    "message": "Transfer in Mempool – wird im nächsten Block verarbeitet",
                })),
            ).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": format!("Mempool-Fehler: {e}"),
            })),
        ).into_response(),
    }
}

/// POST /api/v1/mining/stake — STONE aus der User-Wallet staken
///
/// Erstellt eine Stake-TX für das Wallet des eingeloggten Users.
/// Body: `{ "amount": "500" }`
pub async fn handle_mining_stake(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<StakeRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let user_wallet = user.wallet_address.clone();
    if user_wallet.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": "Kein Wallet zugewiesen" })),
        ).into_response();
    }

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": "Ungültiger Betrag" })),
        ).into_response(),
    };

    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": "Betrag muss positiv sein" })),
        ).into_response();
    }

    // Balance und Nonce atomar berechnen (inkl. Pending-TXs im Mempool)
    let (balance, nonce) = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base_nonce = ledger.nonce(&user_wallet);
        let pending_count = state.node.mempool.sender_pending_count(&user_wallet);
        (ledger.balance(&user_wallet), base_nonce + pending_count)
    };

    if balance < amount {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "Nicht genug Balance für diesen Stake",
            })),
        ).into_response();
    }

    // Validator-Key zum Signieren (Stake/Unstake-TXs werden nach User-Auth
    // vom Node erstellt — Signaturprüfung für diese TX-Typen entfällt)
    let signing_key = load_or_create_validator_key();

    // Stake-TX erstellen – from = User-Wallet
    let tx = match create_signed_tx(
        &signing_key,
        TxType::Stake,
        user_wallet.clone(),
        "pool:staking".to_string(),
        amount,
        rust_decimal::Decimal::ZERO,
        nonce,
        "User Stake".to_string(),
    ) {
        Ok(tx) => tx,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({ "ok": false, "error": format!("TX-Erstellung: {e}") })),
        ).into_response(),
    };

    let tx_id = tx.tx_id.clone();

    let submit_result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx, Some(&ledger))
    };

    match submit_result {
        Ok(_) => {
            println!(
                "[staking] 📥 Stake-TX: {} STONE von {} (TX: {}…)",
                amount, &user_wallet[..16.min(user_wallet.len())], &tx_id[..12]
            );
            (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "tx_id": tx_id,
                    "from": user_wallet,
                    "amount": amount.to_string(),
                    "message": "Stake-TX im Mempool – wird beim nächsten Block verarbeitet",
                })),
            ).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": format!("Mempool: {e}") })),
        ).into_response(),
    }
}

/// POST /api/v1/mining/unstake — STONE aus User-Stake unstaken
///
/// Erstellt eine Unstake-TX für das Wallet des eingeloggten Users.
/// Body: `{ "amount": "200" }`
pub async fn handle_mining_unstake(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<UnstakeRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let user_wallet = user.wallet_address.clone();
    if user_wallet.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": "Kein Wallet zugewiesen" })),
        ).into_response();
    }

    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": "Ungültiger Betrag" })),
        ).into_response(),
    };

    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": "Betrag muss positiv sein" })),
        ).into_response();
    }

    // Staking-Status der User-Wallet prüfen
    {
        let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
        match pool.staker_info(&user_wallet) {
            Some(info) => {
                if info.staked_amount < amount {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({
                            "ok": false,
                            "error": format!("Nicht genug gestaked: {} verfügbar, {} angefordert",
                                info.staked_amount, amount),
                        })),
                    ).into_response();
                }
            }
            None => return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({ "ok": false, "error": "Kein aktiver Stake vorhanden" })),
            ).into_response(),
        }
    }

    // Nonce atomar berechnen (inkl. Pending-TXs im Mempool)
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base_nonce = ledger.nonce(&user_wallet);
        base_nonce + state.node.mempool.sender_pending_count(&user_wallet)
    };

    // Validator-Key zum Signieren (Unstake-TXs werden nach User-Auth
    // vom Node erstellt — Signaturprüfung für diese TX-Typen entfällt)
    let signing_key = load_or_create_validator_key();

    // Unstake-TX erstellen – from = User-Wallet
    let tx = match create_signed_tx(
        &signing_key,
        TxType::Unstake,
        user_wallet.clone(),
        "pool:staking".to_string(),
        amount,
        rust_decimal::Decimal::ZERO,
        nonce,
        "User Unstake".to_string(),
    ) {
        Ok(tx) => tx,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({ "ok": false, "error": format!("TX-Erstellung: {e}") })),
        ).into_response(),
    };

    let tx_id = tx.tx_id.clone();

    let submit_result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx, Some(&ledger))
    };

    match submit_result {
        Ok(_) => {
            println!(
                "[staking] 📤 Unstake-TX: {} STONE von {} (TX: {}…)",
                amount, &user_wallet[..16.min(user_wallet.len())], &tx_id[..12]
            );
            (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "tx_id": tx_id,
                    "from": user_wallet,
                    "amount": amount.to_string(),
                    "lock_period_days": 7,
                    "message": "Unstake-TX im Mempool – 7 Tage Lock nach Verarbeitung",
                })),
            ).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": format!("Mempool: {e}") })),
        ).into_response(),
    }
}

// ─── Mining-Wallet Bindung ────────────────────────────────────────────────────

/// POST /api/v1/mining/bind-wallet — Bindet die Wallet des eingeloggten Users als Mining-Reward-Empfänger.
///
/// Nur ein Admin oder der aktuelle Reward-Wallet-Owner kann die Bindung ändern.
/// Bei der ersten Bindung (kein mining_wallet gesetzt) kann jeder Admin die Wallet binden.
///
/// Body: `{ "wallet": "hex..." }` — muss die wallet_address des eingeloggten Users sein.
pub async fn handle_bind_mining_wallet(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<BindWalletRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // User-Wallet muss übereinstimmen (User kann nur seine eigene Wallet binden)
    if req.wallet != user.wallet_address {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "ok": false,
                "error": "Du kannst nur deine eigene Wallet binden",
                "your_wallet": user.wallet_address,
                "requested_wallet": req.wallet,
            })),
        ).into_response();
    }

    if user.wallet_address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "ok": false, "error": "Kein Wallet zugewiesen" })),
        ).into_response();
    }

    // Wallet-Adresse validieren: muss gültiger 32-Byte Ed25519 Public Key in Hex sein
    if req.wallet.len() != 64
        || !req.wallet.chars().all(|c| c.is_ascii_hexdigit())
    {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "Ungültige Wallet-Adresse (muss 64 Hex-Zeichen / 32-Byte Ed25519 Public Key sein)"
            })),
        ).into_response();
    }

    // Berechtigung prüfen: Admin ODER aktueller Reward-Wallet-Owner
    let is_admin = super::super::auth_middleware::require_admin(&headers, &state).is_ok();
    let current_reward_wallet = state.node.effective_reward_wallet();
    let is_current_owner = user.wallet_address == current_reward_wallet;

    // Prüfen ob bereits eine Mining-Wallet gebunden ist
    let has_binding = state.node.mining_wallet.read().unwrap_or_else(|e| e.into_inner()).is_some();

    if has_binding && !is_admin && !is_current_owner {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "ok": false,
                "error": "Mining-Wallet bereits gebunden. Nur der aktuelle Owner oder Admin kann die Bindung ändern.",
                "current_mining_wallet": current_reward_wallet,
            })),
        ).into_response();
    }

    // Wallet binden
    let new_wallet = Some(req.wallet.clone());
    {
        let mut mw = state.node.mining_wallet.write().unwrap_or_else(|e| e.into_inner());
        *mw = new_wallet.clone();
    }
    stone::master_node::MasterNodeState::save_mining_wallet(&new_wallet);

    println!(
        "[mining] 🔒 Mining-Wallet gebunden: {} (durch User: {})",
        &req.wallet[..16.min(req.wallet.len())],
        user.name,
    );

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "mining_wallet": req.wallet,
            "bound_by": user.name,
            "message": "Mining-Rewards gehen ab sofort an diese Wallet",
        })),
    ).into_response()
}

/// GET /api/v1/mining/wallet — Zeigt die aktuelle Mining-Wallet-Konfiguration.
pub async fn handle_mining_wallet_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let _user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let signing_key = load_or_create_validator_key();
    let validator_wallet = local_validator_pubkey_hex(&signing_key);
    let mining_wallet = state.node.mining_wallet.read().unwrap_or_else(|e| e.into_inner()).clone();
    let effective = state.node.effective_reward_wallet();

    let balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance(&effective).to_string()
    };

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "validator_wallet": validator_wallet,
            "mining_wallet": mining_wallet,
            "effective_reward_wallet": effective,
            "reward_balance": balance,
            "is_bound": mining_wallet.is_some(),
        })),
    ).into_response()
}
