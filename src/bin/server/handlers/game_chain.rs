//! Phase B — HTTP-Endpoints für die On-Chain Game-Registry.
//!
//! Endpunkte:
//!   POST   /api/v1/game-chain/submit        – Signierte CompanyRegister/Update/GameRegister/Update/Deprecate-TX einreichen
//!   GET    /api/v1/companies                 – Alle registrierten Firmen
//!   GET    /api/v1/companies/{wallet}        – Einzelnes Firmenprofil
//!   GET    /api/v1/companies/{wallet}/games  – Alle Spiele dieser Firma
//!   GET    /api/v1/games                     – Alle registrierten Spiele
//!   GET    /api/v1/games/{game_id}           – Einzelner Spiel-Eintrag
//!   GET    /api/v1/account/{wallet}/type     – Account-Typ (personal/company)

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use stone::token::{TokenTx, TxType};

use super::super::state::AppState;

// ─── Submit ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GameChainSubmitRequest {
    /// Vollständig signierte TokenTx mit einem der 5 Game-Chain-TxTypes.
    pub tx: TokenTx,
}

/// POST /api/v1/game-chain/submit
///
/// Nimmt eine signierte Game-Chain-Transaktion entgegen und leitet sie in
/// den Mempool weiter. Akzeptiert nur die 5 TX-Typen aus Phase A.
pub async fn handle_game_chain_submit(
    State(state): State<AppState>,
    Json(req): Json<GameChainSubmitRequest>,
) -> impl IntoResponse {
    let tx = req.tx;

    // Nur Game-Chain-TXs erlauben
    if !matches!(
        tx.tx_type,
        TxType::CompanyRegister | TxType::CompanyUpdate
            | TxType::GameRegister | TxType::GameUpdate | TxType::GameDeprecate
            | TxType::CompanyVerify | TxType::GameVerify
            | TxType::RoleGrant | TxType::RoleRevoke
            | TxType::GameCoinMint | TxType::GameCoinTransfer | TxType::GameCoinBurn
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Nur game_chain-TxTypes erlaubt (company_*, game_*, role_*, gamecoin_*).",
            })),
        ).into_response();
    }

    // Self-TX-Bedingung: gilt für alle AUSSER GameCoinTransfer
    if tx.tx_type != TxType::GameCoinTransfer && tx.from != tx.to {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "from == to erforderlich (Self-TX)",
            })),
        ).into_response();
    }

    // Pool-Adressen blocken
    if tx.from.starts_with("pool:") {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "Pool-Konten dürfen keine Game-Chain-TXs einreichen.",
            })),
        ).into_response();
    }

    // Security Fix: Transaktion validieren (Signatur, TX-ID, Chain-ID) bevor
    // sie ins Mempool kommt. Ohne diesen Check könnten unsignierte oder
    // manipulierte Game-Chain-TXs eingeschleust werden.
    if let Err(e) = stone::token::transaction::validate_tx(&tx) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("TX-Validierung fehlgeschlagen: {e}"),
            })),
        ).into_response();
    }

    // Rate-Limit nach Sender-Adresse — wiederverwendet Transfer-Bucket
    let limiter = &state.rate_limits.transfer;
    if !limiter.check(&tx.from) {
        let retry = limiter.retry_after_secs(&tx.from);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Rate Limit überschritten. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        ).into_response();
    }

    // Mempool mit Ledger-Pre-Check
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    net.broadcast_tx(tx_clone).await;
                });
            }
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "ok": true,
                    "status": "pending",
                    "tx_id": tx.tx_id,
                    "tx_type": tx.tx_type.to_string(),
                })),
            ).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("{e}"),
            })),
        ).into_response(),
    }
}

// ─── Read-Endpunkte ──────────────────────────────────────────────────────────

/// GET /api/v1/companies
pub async fn handle_list_companies(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let mut companies: Vec<&stone::token::CompanyProfile> =
        ledger.all_companies().values().collect();
    companies.sort_by(|a, b| a.registered_at.cmp(&b.registered_at));
    Json(serde_json::json!({
        "ok": true,
        "count": companies.len(),
        "companies": companies,
    })).into_response()
}

/// GET /api/v1/companies/{wallet}
pub async fn handle_get_company(
    State(state): State<AppState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let hex_addr = match stone::token::normalize_address(&wallet) {
        Some(h) => h,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültige Wallet-Adresse" })),
        ).into_response(),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    match ledger.company(&hex_addr) {
        Some(c) => Json(serde_json::json!({
            "ok": true,
            "company": c,
            "display_address": stone::token::display_address(&hex_addr),
            "account_type": "company",
        })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Firma nicht gefunden" })),
        ).into_response(),
    }
}

/// GET /api/v1/companies/{wallet}/games
pub async fn handle_company_games(
    State(state): State<AppState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let hex_addr = match stone::token::normalize_address(&wallet) {
        Some(h) => h,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültige Wallet-Adresse" })),
        ).into_response(),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    if !ledger.is_company(&hex_addr) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Firma nicht gefunden" })),
        ).into_response();
    }
    let games: Vec<&stone::token::OnChainGame> = ledger.games_of_company(&hex_addr);
    Json(serde_json::json!({
        "ok": true,
        "count": games.len(),
        "games": games,
    })).into_response()
}

/// GET /api/v1/games
pub async fn handle_list_games(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let mut games: Vec<&stone::token::OnChainGame> = ledger.all_games().values().collect();
    games.sort_by(|a, b| a.registered_at.cmp(&b.registered_at));
    Json(serde_json::json!({
        "ok": true,
        "count": games.len(),
        "games": games,
    })).into_response()
}

/// GET /api/v1/games/{game_id}
pub async fn handle_get_game(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    match ledger.game(&game_id) {
        Some(g) => Json(serde_json::json!({
            "ok": true,
            "game": g,
        })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Spiel nicht gefunden" })),
        ).into_response(),
    }
}

/// GET /api/v1/account/{wallet}/type
pub async fn handle_account_type(
    State(state): State<AppState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let hex_addr = match stone::token::normalize_address(&wallet) {
        Some(h) => h,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültige Wallet-Adresse" })),
        ).into_response(),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let t = ledger.account_type(&hex_addr);
    Json(serde_json::json!({
        "ok": true,
        "address": hex_addr,
        "account_type": match t {
            stone::token::AccountType::Personal => "personal",
            stone::token::AccountType::Company  => "company",
        },
        "is_company": ledger.is_company(&hex_addr),
    })).into_response()
}

// ─── Phase C: Verifikation + Sub-Keys + Scanner ─────────────────────────────

/// GET /api/v1/games/verified
///
/// Liefert ausschließlich Founder-verifizierte Spiele. Wird vom Scanner
/// in der App genutzt, um vertrauenswürdige Spiele anzuzeigen.
pub async fn handle_list_verified_games(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let mut games: Vec<&stone::token::OnChainGame> = ledger.all_games()
        .values()
        .filter(|g| g.verified)
        .collect();
    games.sort_by(|a, b| a.registered_at.cmp(&b.registered_at));
    Json(serde_json::json!({
        "ok": true,
        "count": games.len(),
        "games": games,
    })).into_response()
}

/// GET /api/v1/companies/{wallet}/roles
///
/// Listet alle Sub-Keys (Rollen) der angegebenen Firma.
pub async fn handle_company_roles(
    State(state): State<AppState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let hex_addr = match stone::token::normalize_address(&wallet) {
        Some(h) => h,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültige Wallet-Adresse" })),
        ).into_response(),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    if !ledger.is_company(&hex_addr) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Firma nicht gefunden" })),
        ).into_response();
    }
    let roles: &[stone::token::SubKey] = ledger.sub_keys_of(&hex_addr);
    Json(serde_json::json!({
        "ok": true,
        "owner_wallet": hex_addr,
        "count": roles.len(),
        "roles": roles,
    })).into_response()
}

/// GET /api/v1/wallet/{wallet}/profile
///
/// Kombiniertes Profil (Round-Trip-optimiert für die Android-App "Einstellungen"):
/// liefert Balance + Nonce + Account-Typ + (falls Firma) Firmenprofil, Spiele,
/// Sub-Keys.
pub async fn handle_wallet_profile(
    State(state): State<AppState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let hex_addr = match stone::token::normalize_address(&wallet) {
        Some(h) => h,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültige Wallet-Adresse" })),
        ).into_response(),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let balance = ledger.balance(&hex_addr).to_string();
    let nonce = ledger.nonce(&hex_addr);
    let acc_type = ledger.account_type(&hex_addr);
    let is_company = matches!(acc_type, stone::token::AccountType::Company);
    let is_founder = ledger.is_founder(&hex_addr);

    let (company, games, roles) = if is_company {
        let c = ledger.company(&hex_addr).cloned();
        let gs: Vec<stone::token::OnChainGame> = ledger.games_of_company(&hex_addr)
            .into_iter().cloned().collect();
        let rs: Vec<stone::token::SubKey> = ledger.sub_keys_of(&hex_addr).to_vec();
        (c, gs, rs)
    } else {
        (None, Vec::new(), Vec::new())
    };
    let games_count = games.len();

    Json(serde_json::json!({
        "ok": true,
        "address": hex_addr,
        "display_address": stone::token::display_address(&hex_addr),
        "balance": balance,
        "nonce": nonce,
        "account_type": match acc_type {
            stone::token::AccountType::Personal => "personal",
            stone::token::AccountType::Company  => "company",
        },
        "is_company": is_company,
        "is_founder": is_founder,
        "company": company,
        "games": games,
        "games_count": games_count,
        "roles": roles,
    })).into_response()
}

// ─── Phase D: Game-Coin Read-Endpoints ──────────────────────────────────────

/// GET /api/v1/games/{game_id}/supply
///
/// Liefert Game-Coin Total-Supply + Halter-Count.
pub async fn handle_game_coin_supply(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    if ledger.game(&game_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Spiel nicht gefunden" })),
        ).into_response();
    }
    let supply = ledger.game_coin_supply(&game_id);
    let holders = ledger.game_coin_holder_count(&game_id);
    Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "total_supply": supply.to_string(),
        "holder_count": holders,
    })).into_response()
}

/// GET /api/v1/games/{game_id}/coins/{wallet}
///
/// Game-Coin-Balance einer Wallet für ein bestimmtes Spiel.
pub async fn handle_game_coin_balance(
    State(state): State<AppState>,
    Path((game_id, wallet)): Path<(String, String)>,
) -> impl IntoResponse {
    let hex_addr = match stone::token::normalize_address(&wallet) {
        Some(h) => h,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültige Wallet-Adresse" })),
        ).into_response(),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    if ledger.game(&game_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Spiel nicht gefunden" })),
        ).into_response();
    }
    let bal = ledger.game_coin_balance(&game_id, &hex_addr);
    Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "wallet": hex_addr,
        "balance": bal.to_string(),
    })).into_response()
}

