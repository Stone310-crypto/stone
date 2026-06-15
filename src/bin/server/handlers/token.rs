//! StoneCoin Token API-Handler
//!
//! Endpunkte:
//!   GET    /api/v1/token/supply               – Supply-Informationen
//!   GET    /api/v1/token/accounts              – Alle Accounts (Admin)
//!   GET    /api/v1/token/pending               – Pending TXs im Mempool
//!   POST   /api/v1/token/transfer              – Token-Transfer einreichen → Mempool
//!   POST   /api/v1/token/faucet                – Testnet-Faucet (aus Community-Pool)
//!   GET    /api/v1/token/history/:address       – TX-Historie eines Accounts
//!   GET    /api/v1/wallet/:address/balance      – Balance eines Accounts
//!   GET    /api/v1/wallet/:address              – Vollständige Account-Info
//!   POST   /api/v1/wallet/create               – Neues Ed25519-Wallet generieren
//!   POST   /api/v1/token/stake                  – Token staken
//!   POST   /api/v1/token/unstake                – Token unstaken
//!   GET    /api/v1/staking/info                 – Staking-Pool Info
//!   GET    /api/v1/staking/pool                 – Detaillierte Pool-Statistiken
//!   GET    /api/v1/staking/staker/:address      – Staker-spezifische Info

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;

use stone::token::{
    AccountInfo, SupplyInfo, TokenTx, TxType, compute_tx_id, default_chain_id,
    TokenLedger, BuyStatus,
    HtlcStore, HtlcStatus, HtlcCreateParams, HtlcClaimParams, HtlcRefundParams,
};

use super::super::auth_middleware::{require_admin, require_user};
use super::super::state::AppState;

// ─── Supply Info ─────────────────────────────────────────────────────────────

/// GET /api/v1/token/supply
pub async fn handle_token_supply(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let pending = state.node.mempool.pending_count();
    let stats = state.node.mempool.stats();
    let info = SupplyInfo::from_ledger(&ledger);
    let network = stone::token::NetworkMode::from_env();
    Json(serde_json::json!({
        "ok": true,
        "network": network.to_string(),
        "supply": info,
        "mempool_pending": pending,
        "mempool_stats": stats,
    }))
}

// ─── Wallet Balance ──────────────────────────────────────────────────────────

/// GET /api/v1/wallet/:address/balance
pub async fn handle_wallet_balance(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    // Akzeptiere sowohl stone1... als auch Hex-Adressen
    let hex_addr = match stone::token::normalize_address(&address) {
        Some(h) => h,
        None => return Json(serde_json::json!({ "ok": false, "error": "Ungültige Adresse" })),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let balance = ledger.balance(&hex_addr);
    let nonce = ledger.nonce(&hex_addr);
    Json(serde_json::json!({
        "ok": true,
        "address": hex_addr,
        "display_address": stone::token::display_address(&hex_addr),
        "balance": balance.to_string(),
        "nonce": nonce,
    }))
}

/// GET /api/v1/wallet/:address
pub async fn handle_wallet_info(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let hex_addr = match stone::token::normalize_address(&address) {
        Some(h) => h,
        None => return Json(serde_json::json!({ "ok": false, "error": "Ungültige Adresse" })),
    };
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let info = AccountInfo {
        address: hex_addr.clone(),
        balance: ledger.balance(&hex_addr),
        nonce: ledger.nonce(&hex_addr),
    };
    Json(serde_json::json!({
        "ok": true,
        "account": info,
        "display_address": stone::token::display_address(&hex_addr),
    }))
}

// ─── Alle Accounts (Admin) ──────────────────────────────────────────────────

/// GET /api/v1/token/accounts — Nur Admin
pub async fn handle_token_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&headers, &state) {
        return e.into_response();
    }
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let accounts = ledger.all_accounts();
    Json(serde_json::json!({
        "ok": true,
        "count": accounts.len(),
        "accounts": accounts,
    })).into_response()
}

// ─── Pending TXs ────────────────────────────────────────────────────────────

/// GET /api/v1/token/pending — Nur authentifizierte User
pub async fn handle_token_pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_user(&headers, &state) {
        return e.into_response();
    }
    let txs = state.node.mempool.pending_txs();
    let items: Vec<serde_json::Value> = txs.iter().map(|tx| {
        serde_json::json!({
            "tx_id": tx.tx_id,
            "tx_type": tx.tx_type,
            "from": tx.from,
            "to": tx.to,
            "amount": tx.amount.to_string(),
            "fee": tx.fee.to_string(),
            "nonce": tx.nonce,
            "timestamp": tx.timestamp,
            "memo": tx.memo,
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "count": items.len(),
        "pending": items,
    }))).into_response()
}

// ─── Token Transfer → Mempool ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TransferRequest {
    /// Vollständig signierte TokenTx (JSON)
    pub tx: TokenTx,
}

/// POST /api/v1/token/transfer
///
/// Nimmt eine bereits signierte Token-Transaktion entgegen,
/// validiert sie und schiebt sie in den Mempool.
/// Die TX wird erst beim nächsten Block-Commit in die Chain aufgenommen.
pub async fn handle_token_transfer(
    State(state): State<AppState>,
    Json(req): Json<TransferRequest>,
) -> impl IntoResponse {
    let tx = req.tx;

    // Nur Transfers, Burns und Key-Rotations erlauben.
    // Stake/Unstake NICHT über diesen Endpoint — nur über die authentifizierten
    // Mining-Handler (/api/v1/mining/stake, /unstake), da Stake/Unstake-TXs
    // serverseitig signiert werden und die Signaturprüfung übersprungen wird.
    // Ohne diese Einschränkung könnte ein Angreifer fremde Wallets staken.
    if tx.tx_type != TxType::Transfer && tx.tx_type != TxType::Burn && tx.tx_type != TxType::RotateKey {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Nur Transfer-, Burn- und RotateKey-Transaktionen können über diesen Endpoint eingereicht werden. Für Staking nutze /api/v1/mining/stake bzw. /unstake.",
            })),
        );
    }

    // Pool-Konten dürfen nicht über den öffentlichen Endpoint genutzt werden.
    // Pool-Transfers werden nur serverseitig erstellt (z.B. Faucet).
    if tx.from.starts_with("pool:") {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "Pool-Konten können nicht über diesen Endpoint transferieren.",
            })),
        );
    }

    // Rate Limiting: per Sender-Adresse
    let rate_key = tx.from.clone();
    let limiter = if tx.tx_type == TxType::RotateKey {
        &state.rate_limits.key_rotation
    } else {
        &state.rate_limits.transfer
    };
    if !limiter.check(&rate_key) {
        let retry = limiter.retry_after_secs(&rate_key);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Rate Limit überschritten. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        );
    }

    // ── Mainnet Guards: Sicherheits-Limits für irreversible Operationen ──
    let network = stone::token::NetworkMode::from_env();
    if !network.is_testnet() {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let sender_balance = ledger.balance(&tx.from);

        // Burn-Limit: max. 10% des Guthabens pro TX im Mainnet
        if tx.tx_type == TxType::Burn {
            let max_burn = sender_balance * rust_decimal::Decimal::new(10, 2); // 10%
            if tx.amount > max_burn {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": format!(
                            "Mainnet-Schutz: Burn max. 10% des Guthabens pro TX ({} STONE). Verfügbar: {} STONE",
                            max_burn, sender_balance
                        ),
                        "max_burn": max_burn.to_string(),
                        "balance": sender_balance.to_string(),
                    })),
                );
            }
        }

        // Transfer-Warnung: TX über 10.000 STONE braucht Bestätigung
        // (Client muss "confirmed: true" im Request mitschicken)
        let large_tx_threshold: rust_decimal::Decimal = "10000".parse().unwrap();
        if tx.tx_type == TxType::Transfer && tx.amount > large_tx_threshold {
            // Warnung ins Log – TX wird trotzdem verarbeitet (Client-Side Bestätigung)
            println!(
                "[token] ⚠️  Mainnet: Große TX von {} → {} über {} STONE (Balance: {})",
                &tx.from[..12.min(tx.from.len())],
                &tx.to[..12.min(tx.to.len())],
                tx.amount,
                sender_balance,
            );
        }
    }

    // In Mempool aufnehmen (mit Ledger Pre-Check)
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            // P2P Broadcast an alle Peers
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
                    "message": "TX im Mempool – wird beim nächsten Block-Commit verarbeitet",
                    "mempool_size": state.node.mempool.pending_count(),
                })),
            )
        }
        Err(e) => {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("{e}"),
                })),
            )
        }
    }
}

// ─── Testnet Faucet ──────────────────────────────────────────────────────────

/// Max. Faucet-Betrag pro Anfrage: 100 STONE
const FAUCET_AMOUNT: &str = "100";

/// Max. Faucet-Guthaben pro Adresse: 1000 STONE (Missbrauchs-Schutz)
const FAUCET_MAX_PER_ADDRESS: &str = "1000";

#[derive(Deserialize)]
pub struct FaucetRequest {
    /// Empfänger-Adresse (Public-Key-Hex)
    pub address: String,
}

/// POST /api/v1/token/faucet
///
/// Gibt Testnet-Token aus dem Community-Pool an eine Adresse.
/// Nur im Testnet-Modus verfügbar.
///
/// Schutzmechanismen:
/// - Nur im Testnet aktiv
/// - Adress-Validierung (64 Hex-Zeichen, kein Pool-Prefix)
/// - Rate Limiting: 1 Anfrage pro Minute pro Adresse
/// - Max. 1000 STONE pro Adresse via Faucet
pub async fn handle_token_faucet(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    // Nur im Testnet erlaubt
    let network = stone::token::NetworkMode::from_env();
    if !network.is_testnet() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "Faucet ist nur im Testnet verfügbar (STONE_NETWORK=testnet)",
            })),
        );
    }

    // Adress-Validierung: stone1... oder 64 Hex-Zeichen, kein Pool-Prefix
    let faucet_addr = match stone::token::normalize_address(&req.address) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Adresse: stone1... oder 64 Hex-Zeichen erwartet",
            })),
        ),
    };

    // Rate Limiting: per Empfänger-Adresse
    if !state.rate_limits.faucet.check(&faucet_addr) {
        let retry = state.rate_limits.faucet.retry_after_secs(&faucet_addr);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Faucet Rate Limit: max. 1 Anfrage pro Minute. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        );
    }

    let amount: rust_decimal::Decimal = FAUCET_AMOUNT.parse().unwrap();
    let max_per_addr: rust_decimal::Decimal = FAUCET_MAX_PER_ADDRESS.parse().unwrap();
    let pool = "pool:community";

    // Max-per-Address Schutz: prüfen ob Adresse schon zu viel bekommen hat
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let current_balance = ledger.balance(&faucet_addr);
        if current_balance + amount > max_per_addr {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!(
                        "Faucet-Limit: max. {} STONE pro Adresse. Aktuelles Guthaben: {}",
                        FAUCET_MAX_PER_ADDRESS,
                        current_balance
                    ),
                    "current_balance": current_balance.to_string(),
                    "max_per_address": FAUCET_MAX_PER_ADDRESS,
                })),
            );
        }
    }

    // ── Faucet-TX erstellen ──
    // Im Testnet: direktes Mint (TxType::Mint) statt Pool-Transfer,
    // da der Community-Pool im Testnet nicht zwingend gefüllt ist.
    // Im Mainnet: Transfer aus pool:community.
    let (from_addr, tx_type) = if network.is_testnet() {
        // Testnet: Mint direkt an Empfänger — kein Pool-Balance nötig
        ("system:faucet".to_string(), TxType::Mint)
    } else {
        // Mainnet: aus Community-Pool transferieren — Balance prüfen
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let available = ledger.balance(pool);
        if available < amount {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("Community-Pool hat nur {} STONE verfügbar", available),
                })),
            );
        }
        (pool.to_string(), TxType::Transfer)
    };

    // Nonce
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(&from_addr);
        base + state.node.mempool.sender_pending_count(&from_addr)
    };

    // TokenTx erstellen
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type,
        from: from_addr,
        to: faucet_addr.clone(),
        amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: "system-faucet".to_string(),
        memo: "Testnet Faucet".to_string(),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Priority,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);

    // In Mempool aufnehmen (mit Ledger Pre-Check)
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            // P2P Broadcast an alle Peers
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    net.broadcast_tx(tx_clone).await;
                });
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "status": "pending",
                    "tx_id": tx.tx_id,
                    "amount": FAUCET_AMOUNT,
                    "to": req.address,
                    "message": "Faucet-TX im Mempool – wird beim nächsten Block verarbeitet und an Peers gesynct",
                })),
            )
        }
        Err(e) => {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("{e}"),
                })),
            )
        }
    }
}

// ─── Wallet erstellen ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletCreateRequest {
    /// Mnemonic-Wortanzahl: 12 oder 24 (Standard: 24)
    #[serde(default = "default_word_count")]
    pub word_count: u16,
}

fn default_word_count() -> u16 { 24 }

/// POST /api/v1/wallet/create
///
/// Generiert ein neues Ed25519-Schlüsselpaar.
/// Gibt Public-Key (Hex) und BIP39-Mnemonic zurück.
/// Der Private Key wird NICHT auf dem Server gespeichert.
///
/// Optionaler Body: `{ "word_count": 12 }` oder `{ "word_count": 24 }` (Default: 24)
pub async fn handle_wallet_create(
    State(state): State<AppState>,
    body: Option<Json<WalletCreateRequest>>,
) -> impl IntoResponse {
    use stone::token::Wallet;

    // Rate Limiting: globaler Key "wallet_create"
    if !state.rate_limits.wallet_create.check("global") {
        let retry = state.rate_limits.wallet_create.retry_after_secs("global");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Wallet-Create Rate Limit überschritten. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        );
    }

    let word_count = body.map(|b| b.word_count).unwrap_or(24);

    // Validierung
    if word_count != 12 && word_count != 24 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "word_count muss 12 oder 24 sein",
            })),
        );
    }

    match Wallet::generate_with_words(word_count) {
        Ok(wallet) => {
            let info = wallet.info(true); // Mnemonic mitgeben bei Erstgenerierung
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "wallet": info,
                    "word_count": word_count,
                    "note": format!(
                        "Bewahre den {}-Wort-Mnemonic sicher auf! Der Private Key wird NICHT auf dem Server gespeichert.",
                        word_count
                    ),
                })),
            )
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("Wallet-Generierung fehlgeschlagen: {e}"),
                })),
            )
        }
    }
}

// ─── TX-History ──────────────────────────────────────────────────────────────

/// GET /api/v1/token/history/:address
///
/// Gibt alle Transaktionen eines Accounts aus der Chain zurück.
pub async fn handle_token_history(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    // Akzeptiere stone1... und Hex
    let hex_addr = match stone::token::normalize_address(&address) {
        Some(h) => h,
        None => return Json(serde_json::json!({ "ok": false, "error": "Ungültige Adresse" })),
    };
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let chain_height = chain.blocks.len() as u64;

    let mut txs: Vec<serde_json::Value> = Vec::new();
    for block in &chain.blocks {
        for tx in &block.transactions {
            if tx.from == hex_addr || tx.to == hex_addr {
                let confirmations = chain_height.saturating_sub(block.index);
                txs.push(serde_json::json!({
                    "tx_id": tx.tx_id,
                    "tx_type": tx.tx_type,
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "nonce": tx.nonce,
                    "timestamp": tx.timestamp,
                    "memo": tx.memo,
                    "block_index": block.index,
                    "confirmations": confirmations,
                    "confirmed": confirmations >= 1,
                }));
            }
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "address": hex_addr,
        "display_address": stone::token::display_address(&hex_addr),
        "count": txs.len(),
        "chain_height": chain_height,
        "transactions": txs,
    }))
}

// ─── TX-Status (by TX-ID) ───────────────────────────────────────────────────

/// GET /api/v1/token/tx/:tx_id
///
/// Gibt den Status einer Transaktion zurück:
/// - `confirmed`: TX in der Chain gefunden (mit Details)
/// - `pending`: TX im Mempool, wartet auf Block
/// - `unknown`: TX weder in Chain noch im Mempool
pub async fn handle_tx_status(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let chain_height = chain.blocks.len() as u64;

    // 1. In der Chain suchen
    for block in chain.blocks.iter().rev() {
        if let Some(tx) = block.transactions.iter().find(|t| t.tx_id == tx_id) {
            let confirmations = chain_height.saturating_sub(block.index);
            return Json(serde_json::json!({
                "ok": true,
                "status": "confirmed",
                "tx_id": tx.tx_id,
                "tx_type": tx.tx_type,
                "from": tx.from,
                "to": tx.to,
                "amount": tx.amount.to_string(),
                "fee": tx.fee.to_string(),
                "nonce": tx.nonce,
                "timestamp": tx.timestamp,
                "memo": tx.memo,
                "block_index": block.index,
                "confirmations": confirmations,
            }));
        }
    }
    drop(chain);

    // 2. Im Mempool suchen
    let pending = state.node.mempool.pending_txs();
    if let Some(tx) = pending.iter().find(|t| t.tx_id == tx_id) {
        return Json(serde_json::json!({
            "ok": true,
            "status": "pending",
            "tx_id": tx.tx_id,
            "tx_type": tx.tx_type,
            "from": tx.from,
            "to": tx.to,
            "amount": tx.amount.to_string(),
            "fee": tx.fee.to_string(),
            "nonce": tx.nonce,
            "timestamp": tx.timestamp,
            "memo": tx.memo,
        }));
    }

    // 3. Bekannt aber schon verarbeitet?
    if state.node.mempool.is_known(&tx_id) {
        return Json(serde_json::json!({
            "ok": true,
            "status": "confirmed",
            "tx_id": tx_id,
            "message": "TX wurde verarbeitet (Details nicht mehr im Mempool)",
        }));
    }

    Json(serde_json::json!({
        "ok": false,
        "status": "unknown",
        "tx_id": tx_id,
        "error": "Transaktion nicht gefunden",
    }))
}

// ─── Key-Rotation Info ───────────────────────────────────────────────────────

/// GET /api/v1/wallet/:address/rotations
///
/// Gibt die Key-Rotation-Historie eines Accounts zurück.
/// Zeigt ob der Key aktiv oder rotiert ist, und welcher Key der Nachfolger ist.
pub async fn handle_wallet_rotations(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());

    let is_rotated = ledger.is_key_rotated(&address);
    let active_key = ledger.resolve_active_key(&address);
    let predecessors = ledger.key_predecessors(&address);

    Json(serde_json::json!({
        "ok": true,
        "address": address,
        "is_active": !is_rotated,
        "is_rotated": is_rotated,
        "active_key": active_key,
        "predecessors": predecessors,
        "predecessor_count": predecessors.len(),
    }))
}

// ─── Einfacher Transfer (Mnemonic → Sign → Submit) ──────────────────────────

#[derive(Deserialize)]
pub struct SendRequest {
    /// BIP39-Mnemonic (12 oder 24 Wörter) des Absenders
    #[serde(default, alias = "phrase")]
    pub mnemonic: String,
    /// Empfänger-Adresse (Public-Key-Hex, 64 Zeichen)
    #[serde(default)]
    pub to: String,
    /// Betrag in STONE
    #[serde(default)]
    pub amount: String,
    /// Absender-Adresse zur Validierung (muss mit Mnemonic übereinstimmen)
    #[serde(default)]
    pub from: String,
    /// Fee-Tier: "express" (0.01), "priority" (0.001), "standard" (0.0)
    #[serde(default)]
    pub fee_tier: Option<String>,
}

/// POST /api/v1/token/send
///
/// Vereinfachter Transfer-Endpoint für die Web-UI:
/// Empfängt Mnemonic + Empfänger + Betrag, rekonstruiert das Wallet,
/// signiert die TX serverseitig und reicht sie in den Mempool ein.
///
/// ⚠ Der Mnemonic wird nur im RAM verarbeitet und NICHT gespeichert.
pub async fn handle_token_send(
    State(state): State<AppState>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_token_send")
        ));
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_token_send");
    use stone::token::Wallet;

    // Mnemonic prüfen
    if req.mnemonic.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Mnemonic fehlt",
            })),
        );
    }

    // Empfänger-Adresse validieren (stone1... oder Hex)
    let to_hex = match stone::token::normalize_address(&req.to) {
        Some(h) if h.len() == 64 => h,
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Empfänger-Adresse: stone1... oder 64 Hex-Zeichen erwartet",
            })),
        ),
    };

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültiger Betrag",
            })),
        ),
    };

    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Betrag muss positiv sein",
            })),
        );
    }

    // Wallet aus Mnemonic wiederherstellen
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Ungültiger Mnemonic: {e}"),
            })),
        ),
    };

    // Optional: from-Adresse gegen Wallet-Adresse prüfen (akzeptiert stone1... und Hex)
    if !req.from.is_empty() {
        let from_hex = stone::token::normalize_address(&req.from).unwrap_or_default();
        if from_hex != wallet.address() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "Absender-Adresse stimmt nicht mit dem Mnemonic überein. Falscher Mnemonic?",
                })),
            );
        }
    }

    // Rate Limiting per Sender
    if !state.rate_limits.transfer.check(&wallet.address()) {
        let retry = state.rate_limits.transfer.retry_after_secs(&wallet.address());
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Rate Limit überschritten. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        );
    }

    // Nonce aus dem Ledger holen (+ pending TXs im Mempool vom selben Sender)
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(&wallet.address());
        base + state.node.mempool.sender_pending_count(&wallet.address())
    };

    // Fee-Tier parsen
    let tier = match req.fee_tier.as_deref() {
        Some("express") | Some("priority") => stone::token::FeeTier::Priority,
        Some("standard") | None => stone::token::FeeTier::Standard,
        Some("verified") => stone::token::FeeTier::Verified,
        Some(other) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Unbekannter fee_tier: '{}'. Erlaubt: priority, standard", other),
            })),
        ),
    };

    // TX signieren mit Fee-Tier
    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer,
        to_hex.clone(),
        amount,
        nonce,
        String::new(),
        tier,
    ) {
        Ok(t) => t,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("TX-Signierung fehlgeschlagen: {e}"),
            })),
        ),
    };

    // In Mempool aufnehmen
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            // P2P Broadcast
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
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "fee_tier": tx.fee_tier.to_string(),
                    "message": match tx.fee_tier {
                        stone::token::FeeTier::Priority => "Priority-TX im Mempool – wird im nächsten Block verarbeitet",
                        stone::token::FeeTier::Standard => "Standard-TX im Mempool – wird beim nächsten Dokument-Upload verarbeitet",
                        stone::token::FeeTier::Verified => "Verified-TX im Mempool – priorisierte Verarbeitung (50% Fee-Rabatt)",
                    },
                })),
            )
        }
        Err(e) => {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("{e}"),
                })),
            )
        }
    }
}

// ─── Authentifizierter Transfer (API-Key + Phrase via Proxy) ─────────────────

#[derive(Deserialize)]
pub struct SendAuthenticatedRequest {
    /// Empfänger-Adresse (Public-Key-Hex, 64 Zeichen)
    #[serde(default)]
    pub to: String,
    /// Betrag in STONE
    #[serde(default)]
    pub amount: String,
    /// Fee-Tier: "express", "priority", "standard"
    #[serde(default = "default_fee_tier")]
    pub fee_tier: String,
    /// Mnemonic — wird vom Flask-Proxy aus der verschlüsselten Session injiziert
    /// (nie vom Browser direkt gesendet!)
    #[serde(default, alias = "phrase")]
    pub mnemonic: String,
}

fn default_fee_tier() -> String { "standard".to_string() }

/// POST /api/v1/token/send-authenticated
///
/// Wie `/api/v1/token/send`, aber ohne `from`-Feld. Der Absender wird aus
/// dem Mnemonic abgeleitet. Designed für den Flask-Proxy der den Mnemonic
/// aus der Server-Session injiziert — der Browser schickt ihn nie.
///
/// Body: { "to": "...", "amount": "10", "fee_tier": "priority", "mnemonic": "..." }
pub async fn handle_token_send_authenticated(
    State(state): State<AppState>,
    Json(req): Json<SendAuthenticatedRequest>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_token_send_authenticated")
        ));
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_token_send_authenticated");
    use stone::token::Wallet;

    // Mnemonic prüfen (wird vom Flask-Proxy injiziert)
    if req.mnemonic.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Nicht authentifiziert — bitte erneut einloggen",
                "login_required": true,
            })),
        );
    }

    // Empfänger validieren (stone1... oder Hex)
    let to_hex = match stone::token::normalize_address(&req.to) {
        Some(h) if h.len() == 64 => h,
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Empfänger-Adresse: stone1... oder 64 Hex-Zeichen erwartet",
            })),
        ),
    };

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültiger Betrag" })),
        ),
    };
    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Betrag muss positiv sein" })),
        );
    }

    // Fee-Tier
    let tier = match req.fee_tier.as_str() {
        "express" | "priority" => stone::token::FeeTier::Priority,
        "standard" => stone::token::FeeTier::Standard,
        "verified" => stone::token::FeeTier::Verified,
        other => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Unbekannter fee_tier: '{}'. Erlaubt: priority, standard", other),
            })),
        ),
    };

    // Wallet rekonstruieren
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": format!("Session-Fehler: {e}") })),
        ),
    };

    // Rate Limiting
    if !state.rate_limits.transfer.check(&wallet.address()) {
        let retry = state.rate_limits.transfer.retry_after_secs(&wallet.address());
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Rate Limit überschritten. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        );
    }

    // Nonce (Ledger + pending TXs im Mempool)
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(&wallet.address());
        base + state.node.mempool.sender_pending_count(&wallet.address())
    };

    // TX signieren
    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer,
        to_hex.clone(),
        amount,
        nonce,
        String::new(),
        tier,
    ) {
        Ok(t) => t,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("TX-Signierung fehlgeschlagen: {e}") })),
        ),
    };

    // In Mempool
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move { net.broadcast_tx(tx_clone).await; });
            }
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "ok": true,
                    "status": "pending",
                    "tx_id": tx.tx_id,
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "fee_tier": tx.fee_tier.to_string(),
                    "message": match tx.fee_tier {
                        stone::token::FeeTier::Priority => "Priority-TX – wird im nächsten Block verarbeitet",
                        stone::token::FeeTier::Standard => "Standard-TX – wird beim nächsten Dokument-Upload verarbeitet",
                        stone::token::FeeTier::Verified => "Verified-TX – priorisierte Verarbeitung (50% Fee-Rabatt)",
                    },
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

// ─── Staking API-Handler ─────────────────────────────────────────────────────

// SECURITY: handle_token_stake und handle_token_unstake wurden entfernt.
// Diese Endpoints akzeptierten raw TXs ohne Auth und ohne Signaturprüfung.
// Staking/Unstaking erfolgt ausschließlich über die authentifizierten
// /api/v1/mining/stake und /api/v1/mining/unstake Endpoints.

/// GET /api/v1/staking/info
///
/// Öffentliche Staking-Pool-Übersicht: Gesamt-Stake, APY, Epoch, etc.
pub async fn handle_staking_info(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
    let reward_pool_balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance("pool:mining_rewards")
    };

    let info = pool.pool_info(reward_pool_balance);
    (StatusCode::OK, Json(serde_json::json!(info)))
}

/// GET /api/v1/staking/pool
///
/// Detaillierte Pool-Statistiken inkl. Top-Staker.
pub async fn handle_staking_pool(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
    let reward_pool_balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance("pool:mining_rewards")
    };

    let info = pool.pool_info(reward_pool_balance);
    let top_stakers = pool.top_stakers(20);

    (StatusCode::OK, Json(serde_json::json!({
        "pool": info,
        "top_stakers": top_stakers,
        "unstake_queue_size": pool.unstake_queue.len(),
    })))
}

/// GET /api/v1/staking/staker/:address
///
/// Staker-spezifische Informationen.
pub async fn handle_staker_info(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    // Akzeptiere stone1... und Hex
    let hex_addr = stone::token::normalize_address(&address).unwrap_or(address.clone());
    let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());

    match pool.staker_info(&hex_addr) {
        Some(info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "staker": info,
                "display_address": stone::token::display_address(&hex_addr),
            })),
        ),
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "staker": {
                    "address": hex_addr,
                    "display_address": stone::token::display_address(&hex_addr),
                    "staked_amount": "0",
                    "pending_rewards": "0",
                    "total_rewards": "0",
                    "staked_since": 0,
                    "unstake_requests": [],
                    "share_percent": "0",
                    "stake_level": "observer",
                },
            })),
        ),
    }
}

/// POST /api/v1/admin/ledger/rebuild
///
/// Forciert einen kompletten Ledger-Rebuild aus der Chain.
/// Behebt Desync-Probleme zwischen token_db und Chain-State.
pub async fn handle_ledger_rebuild(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let blocks = &chain.blocks;

    let old_supply = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.total_supply()
    };

    let rebuilt = TokenLedger::rebuild_from_chain(blocks);
    let new_supply = rebuilt.total_supply();
    let account_count = rebuilt.account_count();

    {
        let mut ledger = state.node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
        *ledger = rebuilt;
    }

    Json(serde_json::json!({
        "ok": true,
        "message": "Ledger aus Chain neu aufgebaut",
        "old_supply": old_supply.to_string(),
        "new_supply": new_supply.to_string(),
        "accounts": account_count,
        "blocks_processed": blocks.len(),
    }))
}

// ─── Mempool Sync (Peer-to-Peer) ────────────────────────────────────────────

/// GET /api/v1/mempool/sync — Öffentlich (keine Auth nötig)
///
/// Gibt alle pending TXs als vollständige TokenTx-Objekte zurück.
/// Wird von Minern genutzt um TXs von entfernten Nodes zu synchronisieren.
/// Sicher weil alle TXs bereits signiert sind und via Gossip öffentlich verteilt werden.
pub async fn handle_mempool_sync(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let txs = state.node.mempool.pending_txs();
    // Alle User-TXs zurückgeben — nur System-TXs (Reward/Mint/Memorial) ausschließen
    let user_txs: Vec<&stone::token::TokenTx> = txs.iter()
        .filter(|tx| !matches!(tx.tx_type,
            stone::token::TxType::Reward
            | stone::token::TxType::Mint
            | stone::token::TxType::Memorial
        ))
        .collect();
    (StatusCode::OK, Json(serde_json::json!(user_txs))).into_response()
}

// ─── Admin Airdrop (aus beliebigem Pool) ─────────────────────────────────────

#[derive(Deserialize)]
pub struct AirdropRequest {
    /// Empfänger-Adresse (64 Hex-Zeichen)
    pub to: String,
    /// Betrag in STONE (z.B. "5000000")
    pub amount: String,
    /// Quell-Pool (z.B. "pool:founders", "pool:community", "pool:treasury")
    #[serde(default = "default_airdrop_pool")]
    pub from_pool: String,
    /// Optionale Notiz
    #[serde(default)]
    pub memo: String,
}

fn default_airdrop_pool() -> String {
    "pool:founders".to_string()
}

/// POST /api/v1/admin/airdrop
///
/// Admin-Only: Verteilt STONE aus einem Pool-Konto an eine Wallet.
/// Benötigt `x-api-key` Header mit dem Admin-Key.
///
/// Body: `{ "to": "<hex64>", "amount": "1000", "from_pool": "pool:founders", "memo": "Beta Airdrop" }`
pub async fn handle_admin_airdrop(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AirdropRequest>,
) -> impl IntoResponse {
    // Admin-Auth erforderlich
    if let Err(e) = require_admin(&headers, &state) {
        return e.into_response();
    }

    // Adress-Validierung (stone1... oder Hex)
    let to_hex = match stone::token::normalize_address(&req.to) {
        Some(h) if h.len() == 64 => h,
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Empfänger-Adresse: stone1... oder 64 Hex-Zeichen erwartet",
            })),
        ).into_response(),
    };

    // Pool-Validierung: nur bekannte Pools erlauben
    let allowed_pools = [
        "pool:founders", "pool:community", "pool:treasury",
        "pool:liquidity", "pool:node_operators",
    ];
    if !allowed_pools.contains(&req.from_pool.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Ungültiger Pool: {}. Erlaubt: {:?}", req.from_pool, allowed_pools),
            })),
        ).into_response();
    }

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Ungültiger Betrag" })),
        ).into_response(),
    };

    if amount <= rust_decimal::Decimal::ZERO {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Betrag muss positiv sein" })),
        ).into_response();
    }

    // Pool-Balance prüfen
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let available = ledger.balance(&req.from_pool);
        if available < amount {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("{} hat nur {} STONE verfügbar", req.from_pool, available),
                    "available": available.to_string(),
                })),
            ).into_response();
        }
    }

    // Nonce berechnen
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&req.from_pool) + state.node.mempool.sender_pending_count(&req.from_pool)
    };

    let memo = if req.memo.is_empty() {
        format!("Admin Airdrop aus {}", req.from_pool)
    } else {
        req.memo.clone()
    };

    // TX erstellen (Pool-Signatur wird in verify_tx_signature übersprungen)
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: req.from_pool.clone(),
        to: to_hex.clone(),
        amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: "admin-airdrop".to_string(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);

    let tx_id = tx.tx_id.clone();

    // In Mempool aufnehmen
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            println!(
                "[airdrop] ✈️  {} STONE: {} → {} (TX: {}…)",
                amount, req.from_pool, &req.to[..16], &tx_id[..12]
            );

            // P2P Broadcast
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx;
                tokio::spawn(async move {
                    net.broadcast_tx(tx_clone).await;
                });
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "tx_id": tx_id,
                    "from": req.from_pool,
                    "to": req.to,
                    "amount": amount.to_string(),
                    "message": "Airdrop-TX im Mempool – wird beim nächsten Block verarbeitet",
                })),
            ).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ).into_response(),
    }
}

// ─── Testnet-Markt-Simulation ────────────────────────────────────────────────
// Entfernen: Diesen Block + Routen in router.rs löschen.

/// GET /api/v1/token/market
pub async fn handle_market_info(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let market = state.node.testnet_market.read().unwrap_or_else(|e| e.into_inner());
    if !market.config.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Market simulation disabled" })),
        ).into_response();
    }
    let info = market.market_info();
    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "market": info }))).into_response()
}

/// GET /api/v1/token/market/history?count=100
pub async fn handle_market_history(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let market = state.node.testnet_market.read().unwrap_or_else(|e| e.into_inner());
    if !market.config.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Market simulation disabled" })),
        ).into_response();
    }
    let count: usize = params.get("count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let history: Vec<_> = market.history.iter().rev().take(count).collect();
    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "count": history.len(),
        "points": history,
    }))).into_response()
}

// ─── Markt: Echte Trades (Kauf/Verkauf mit realen STONE-TXs) ────────────────

#[derive(Deserialize)]
pub struct MarketBuyRequest {
    /// Wallet-Adresse des Käufers (hex)
    pub address: String,
    /// STONE-Menge die gekauft werden soll
    pub amount: String,
}

#[derive(Deserialize)]
pub struct MarketSellRequest {
    /// Wallet-Adresse des Verkäufers (hex)
    pub address: String,
    /// STONE-Menge die verkauft werden soll
    pub amount: String,
}

/// POST /api/v1/token/market/buy
///
/// Kauft STONE mit TC$ (Testnet-Dollar). Erstellt eine echte Blockchain-TX
/// von pool:market_reserve → Käufer-Adresse.
pub async fn handle_market_buy(
    State(state): State<AppState>,
    Json(req): Json<MarketBuyRequest>,
) -> impl IntoResponse {
    // Nur im Testnet
    let network = stone::token::NetworkMode::from_env();
    if !network.is_testnet() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "ok": false, "error": "Markt-Trading nur im Testnet verfügbar"
        }))).into_response();
    }

    // Adresse normalisieren
    let buyer_addr = match stone::token::normalize_address(&req.address) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültige Wallet-Adresse"
        }))).into_response(),
    };

    // Betrag parsen
    let stone_amount: f64 = match req.amount.parse() {
        Ok(a) if a > 0.0 => a,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiger Betrag"
        }))).into_response(),
    };

    let decimal_amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiger Betrag"
        }))).into_response(),
    };

    // TC$-Balance prüfen & Preis ermitteln
    let (price, _total_tc, _fee) = {
        let mut market = state.node.testnet_market.write().unwrap_or_else(|e| e.into_inner());
        match market.prepare_buy(&buyer_addr, stone_amount) {
            Ok(result) => result,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false, "error": e
            }))).into_response(),
        }
    };

    // Pool-Balance prüfen
    let pool_addr = stone::token::MARKET_RESERVE_POOL;
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let available = ledger.balance(pool_addr);
        if available < decimal_amount {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false,
                "error": format!("Market-Reserve hat nicht genug STONE ({} verfügbar)", available),
            }))).into_response();
        }
    }

    // Nonce für pool:market_reserve
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(pool_addr) + state.node.mempool.sender_pending_count(pool_addr)
    };

    // Echte STONE-TX erstellen: pool:market_reserve → buyer
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: pool_addr.to_string(),
        to: buyer_addr.clone(),
        amount: decimal_amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: "market-buy".to_string(),
        memo: format!("Market Buy: {} STONE @ {:.6} TC$", stone_amount, price),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);
    let tx_id = tx.tx_id.clone();

    // In Mempool
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            // P2P Broadcast
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx;
                tokio::spawn(async move { net.broadcast_tx(tx_clone).await; });
            }

            // TC$ abbuchen + Trade speichern
            let trade_result = {
                let mut market = state.node.testnet_market.write().unwrap_or_else(|e| e.into_inner());
                let result = market.confirm_buy(&buyer_addr, stone_amount, price, &tx_id);
                let _ = market.save();
                result
            };

            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "trade": trade_result,
                "message": "Kauf ausgeführt – STONE werden beim nächsten Block gutgeschrieben",
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Mempool: {e}")
        }))).into_response(),
    }
}

/// POST /api/v1/token/market/sell
///
/// Verkauft STONE für TC$ (Testnet-Dollar). Erstellt eine echte Blockchain-TX
/// vom User → pool:market_reserve. Erfordert Signatur des Verkäufers.
pub async fn handle_market_sell(
    State(state): State<AppState>,
    Json(req): Json<MarketSellRequest>,
) -> impl IntoResponse {
    let network = stone::token::NetworkMode::from_env();
    if !network.is_testnet() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "ok": false, "error": "Markt-Trading nur im Testnet verfügbar"
        }))).into_response();
    }

    let seller_addr = match stone::token::normalize_address(&req.address) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültige Wallet-Adresse"
        }))).into_response(),
    };

    let stone_amount: f64 = match req.amount.parse() {
        Ok(a) if a > 0.0 => a,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiger Betrag"
        }))).into_response(),
    };

    let decimal_amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) => a,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiger Betrag"
        }))).into_response(),
    };

    // STONE-Balance prüfen
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let available = ledger.balance(&seller_addr);
        if available < decimal_amount {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false,
                "error": format!("Nicht genug STONE: {} verfügbar", available),
            }))).into_response();
        }
    }

    // Preis ermitteln
    let (price, _total_tc, _fee) = {
        let market = state.node.testnet_market.read().unwrap_or_else(|e| e.into_inner());
        match market.prepare_sell(&seller_addr, stone_amount) {
            Ok(result) => result,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false, "error": e
            }))).into_response(),
        }
    };

    // Nonce für den Verkäufer
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&seller_addr) + state.node.mempool.sender_pending_count(&seller_addr)
    };

    // Echte TX: seller → pool:market_reserve
    let pool_addr = stone::token::MARKET_RESERVE_POOL;
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: seller_addr.clone(),
        to: pool_addr.to_string(),
        amount: decimal_amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: "market-sell".to_string(),
        memo: format!("Market Sell: {} STONE @ {:.6} TC$", stone_amount, price),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);
    let tx_id = tx.tx_id.clone();

    // In Mempool (Signatur wird hier validiert)
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx;
                tokio::spawn(async move { net.broadcast_tx(tx_clone).await; });
            }

            // TC$ gutschreiben + Trade speichern
            let trade_result = {
                let mut market = state.node.testnet_market.write().unwrap_or_else(|e| e.into_inner());
                let result = market.confirm_sell(&seller_addr, stone_amount, price, &tx_id);
                let _ = market.save();
                result
            };

            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "trade": trade_result,
                "message": "Verkauf ausgeführt – TC$ wurden gutgeschrieben",
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Mempool: {e}")
        }))).into_response(),
    }
}

/// GET /api/v1/token/market/balance?address=...
///
/// Gibt TC$-Guthaben, Trade-Historie und Portfolio-Übersicht zurück.
pub async fn handle_market_balance(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let address = match params.get("address") {
        Some(a) => match stone::token::normalize_address(a) {
            Some(h) if h.len() == 64 => h,
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false, "error": "Ungültige Adresse"
            }))).into_response(),
        },
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "address Parameter fehlt"
        }))).into_response(),
    };

    let market = state.node.testnet_market.read().unwrap_or_else(|e| e.into_inner());
    let balance = market.market_balance(&address);

    // Echte STONE-Balance aus dem Ledger
    let stone_balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance(&address).to_string()
    };

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "balance": balance,
        "stone_balance": stone_balance,
    }))).into_response()
}

// ─── HTLC (Hash Time-Locked Contracts) ──────────────────────────────────────

#[derive(Deserialize)]
pub struct HtlcCreateRequest {
    /// Sender Wallet-Adresse (hex)
    pub from: String,
    /// Empfänger Wallet-Adresse (hex) — leer für offenen Trade
    #[serde(default)]
    pub to: String,
    /// Betrag in STONE
    pub amount: String,
    /// SHA-256 Hash-Lock (64 hex chars)
    pub hash_lock: String,
    /// Time-Lock als Unix-Timestamp (absolute Ablaufzeit)
    pub time_lock: i64,
    /// Ed25519-Signatur des Senders (hex)
    pub signature: String,
    /// Nonce des Senders
    pub nonce: u64,
    /// Timestamp der TX (Client-Zeitstempel, muss zur Signatur passen)
    pub timestamp: i64,
    /// Preimage für Auto-Buy (optional, wird server-seitig gespeichert)
    #[serde(default)]
    pub preimage: String,
    /// Preis in externer Währung (optional, für P2P-Käufe)
    #[serde(default)]
    pub price_amount: Option<String>,
    /// Asset-Name (z.B. "USDT", "USDC", "ETH")
    #[serde(default)]
    pub price_asset: Option<String>,
    /// Blockchain-Netzwerk für Zahlung (z.B. "polygon", "ethereum")
    #[serde(default)]
    pub price_chain: Option<String>,
}

#[derive(Deserialize)]
pub struct HtlcClaimRequest {
    /// HTLC Contract-ID
    pub htlc_id: String,
    /// Preimage (hex) das zum Hash-Lock passt
    pub preimage: String,
    /// Ziel-Wallet für offene Trades (wenn kein Empfänger im HTLC)
    #[serde(default)]
    pub claim_wallet: String,
}

#[derive(Deserialize)]
pub struct HtlcRefundRequest {
    /// HTLC Contract-ID
    pub htlc_id: String,
}

/// POST /api/v1/htlc/create
///
/// Erstellt einen neuen HTLC-Contract. Sender schickt STONE an pool:htlc_escrow
/// mit Hash-Lock und Time-Lock. Erfordert Signatur des Senders.
pub async fn handle_htlc_create(
    State(state): State<AppState>,
    Json(req): Json<HtlcCreateRequest>,
) -> impl IntoResponse {
    use stone::token::htlc::HTLC_ESCROW_POOL;

    // Adresse normalisieren
    let sender = match stone::token::normalize_address(&req.from) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültige Sender-Adresse"
        }))).into_response(),
    };
    // Empfänger: leer = offener Trade (jeder kann claimen)
    let receiver = if req.to.is_empty() {
        String::new()
    } else {
        match stone::token::normalize_address(&req.to) {
            Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false, "error": "Ungültige Empfänger-Adresse"
            }))).into_response(),
        }
    };

    // Betrag parsen
    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) if a > rust_decimal::Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiger Betrag"
        }))).into_response(),
    };

    // Hash-Lock validieren
    if req.hash_lock.len() != 64 || !req.hash_lock.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "hash_lock muss 64 Hex-Zeichen sein (SHA-256)"
        }))).into_response();
    }

    // Time-Lock validieren
    let now = chrono::Utc::now().timestamp();
    if req.time_lock <= now {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "time_lock muss in der Zukunft liegen"
        }))).into_response();
    }

    // Preis-Info bauen (optional)
    let trade_price = match (&req.price_amount, &req.price_asset, &req.price_chain) {
        (Some(amt), Some(asset), Some(chain)) if !amt.is_empty() && !asset.is_empty() && !chain.is_empty() => {
            // Asset und Chain validieren
            let asset_upper = asset.to_uppercase();
            let chain_lower = chain.to_lowercase();
            if !stone::token::htlc::SUPPORTED_ASSETS.contains(&asset_upper.as_str()) {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "ok": false, "error": format!("Nicht unterstütztes Asset: {asset}. Erlaubt: {:?}", stone::token::htlc::SUPPORTED_ASSETS)
                }))).into_response();
            }
            if !stone::token::htlc::SUPPORTED_CHAINS.contains(&chain_lower.as_str()) {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "ok": false, "error": format!("Nicht unterstützte Chain: {chain}. Erlaubt: {:?}", stone::token::htlc::SUPPORTED_CHAINS)
                }))).into_response();
            }
            // Betrag validieren
            if amt.parse::<rust_decimal::Decimal>().is_err() {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "ok": false, "error": "Ungültiger Preisbetrag"
                }))).into_response();
            }
            Some(stone::token::TradePrice {
                amount: amt.clone(),
                asset: asset_upper,
                chain: chain_lower,
            })
        }
        _ => None,
    };

    // Memo bauen
    let memo = serde_json::to_string(&HtlcCreateParams {
        hash_lock: req.hash_lock.clone(),
        time_lock: req.time_lock,
        receiver: receiver.clone(),
        price: trade_price,
    }).unwrap_or_default();

    // Timestamp validieren: nicht älter als 5 Min, nicht mehr als 5 Min in der Zukunft
    if (now - req.timestamp).abs() > 300 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Timestamp zu weit vom Server-Zeitpunkt entfernt"
        }))).into_response();
    }

    // TX erstellen
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::HtlcCreate,
        from: sender.clone(),
        to: HTLC_ESCROW_POOL.to_string(),
        amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce: req.nonce,
        timestamp: req.timestamp,
        signature: req.signature.clone(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);
    let tx_id = tx.tx_id.clone();

    // In Mempool
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            // P2P Broadcast
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx;
                tokio::spawn(async move { net.broadcast_tx(tx_clone).await; });
            }

            // Preimage für Auto-Buy speichern (bei offenen Trades)
            let htlc_id = format!("htlc-{}", &tx_id[..16]);
            if !req.preimage.is_empty() {
                if HtlcStore::verify_preimage(&req.hash_lock, &req.preimage) {
                    let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
                    store.store_preimage(&htlc_id, req.preimage.clone());
                    if let Err(e) = store.persist() {
                        eprintln!("[htlc] ⚠️  Preimage persist fehlgeschlagen: {e}");
                    }
                }
            }

            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "tx_id": tx_id,
                "htlc_id": htlc_id,
                "message": "HTLC erstellt – wird im nächsten Block aktiviert",
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Mempool: {e}")
        }))).into_response(),
    }
}

/// POST /api/v1/htlc/claim
///
/// Claimed einen HTLC-Contract mit dem korrekten Preimage.
/// Erstellt eine System-TX: pool:htlc_escrow → Empfänger.
pub async fn handle_htlc_claim(
    State(state): State<AppState>,
    Json(req): Json<HtlcClaimRequest>,
) -> impl IntoResponse {
    use stone::token::htlc::HTLC_ESCROW_POOL;

    // HTLC im Store prüfen
    let contract = {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        store.get(&req.htlc_id).cloned()
    };

    let contract = match contract {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false, "error": "HTLC nicht gefunden"
        }))).into_response(),
    };

    if contract.status != HtlcStatus::Locked {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("HTLC Status ist {:?}, erwartet Locked", contract.status)
        }))).into_response();
    }

    // Preimage vorab prüfen
    if !stone::token::htlc::HtlcStore::verify_preimage(&contract.hash_lock, &req.preimage) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiges Preimage – Hash stimmt nicht überein"
        }))).into_response();
    }

    // Time-Lock prüfen
    let now = chrono::Utc::now().timestamp();
    if now >= contract.time_lock {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "HTLC ist abgelaufen – nur noch Refund möglich"
        }))).into_response();
    }

    // Memo bauen
    let memo = serde_json::to_string(&HtlcClaimParams {
        htlc_id: req.htlc_id.clone(),
        preimage: req.preimage.clone(),
    }).unwrap_or_default();

    // Empfänger bestimmen: bei offenem Trade → claim_wallet verwenden
    let claim_to = if contract.receiver.is_empty() {
        match stone::token::normalize_address(&req.claim_wallet) {
            Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false, "error": "claim_wallet fehlt oder ungültig – bei offenem Trade erforderlich"
            }))).into_response(),
        }
    } else {
        contract.receiver.clone()
    };

    // System-TX erstellen
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::HtlcClaim,
        from: HTLC_ESCROW_POOL.to_string(),
        to: claim_to,
        amount: contract.amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce: 0,
        timestamp: now,
        signature: "system".to_string(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);
    let tx_id = tx.tx_id.clone();

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx;
                tokio::spawn(async move { net.broadcast_tx(tx_clone).await; });
            }

            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "tx_id": tx_id,
                "htlc_id": req.htlc_id,
                "message": "HTLC claimed – STONE werden im nächsten Block übertragen",
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Mempool: {e}")
        }))).into_response(),
    }
}

/// POST /api/v1/htlc/refund
///
/// Refunded einen abgelaufenen HTLC-Contract.
/// Erstellt eine System-TX: pool:htlc_escrow → Original-Sender.
pub async fn handle_htlc_refund(
    State(state): State<AppState>,
    Json(req): Json<HtlcRefundRequest>,
) -> impl IntoResponse {
    use stone::token::htlc::HTLC_ESCROW_POOL;

    let contract = {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        store.get(&req.htlc_id).cloned()
    };

    let contract = match contract {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false, "error": "HTLC nicht gefunden"
        }))).into_response(),
    };

    if contract.status != HtlcStatus::Locked {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("HTLC Status ist {:?}, erwartet Locked", contract.status)
        }))).into_response();
    }

    let now = chrono::Utc::now().timestamp();
    if now < contract.time_lock {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false,
            "error": "HTLC ist noch nicht abgelaufen",
            "expires_at": contract.time_lock,
            "seconds_remaining": contract.time_lock - now,
        }))).into_response();
    }

    let memo = serde_json::to_string(&HtlcRefundParams {
        htlc_id: req.htlc_id.clone(),
    }).unwrap_or_default();

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::HtlcRefund,
        from: HTLC_ESCROW_POOL.to_string(),
        to: contract.sender.clone(),
        amount: contract.amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce: 0,
        timestamp: now,
        signature: "system".to_string(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);
    let tx_id = tx.tx_id.clone();

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx;
                tokio::spawn(async move { net.broadcast_tx(tx_clone).await; });
            }

            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "tx_id": tx_id,
                "htlc_id": req.htlc_id,
                "message": "HTLC refunded – STONE werden im nächsten Block zurückerstattet",
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Mempool: {e}")
        }))).into_response(),
    }
}

/// POST /api/v1/htlc/buy
///
/// Kauft einen offenen HTLC-Trade automatisch.
/// Server nutzt das gespeicherte Preimage, Käufer muss es nicht kennen.
#[derive(Deserialize)]
pub struct HtlcBuyRequest {
    /// HTLC Contract-ID
    pub htlc_id: String,
    /// Wallet-Adresse des Käufers (dort landen die STONE)
    pub buyer_wallet: String,
}

pub async fn handle_htlc_buy(
    State(state): State<AppState>,
    Json(req): Json<HtlcBuyRequest>,
) -> impl IntoResponse {
    use stone::token::htlc::HTLC_ESCROW_POOL;

    // Käufer-Wallet validieren
    let buyer = match stone::token::normalize_address(&req.buyer_wallet) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültige buyer_wallet"
        }))).into_response(),
    };

    // HTLC-Contract laden
    let contract = {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        store.get(&req.htlc_id).cloned()
    };

    let contract = match contract {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false, "error": "HTLC nicht gefunden"
        }))).into_response(),
    };

    if contract.status != HtlcStatus::Locked {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("HTLC Status ist {:?}, erwartet Locked", contract.status)
        }))).into_response();
    }

    // Nur offene Trades (kein fester Empfänger)
    if !contract.receiver.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Kein offener Trade – dieser HTLC hat bereits einen Empfänger"
        }))).into_response();
    }

    // Käufer darf nicht Sender sein
    if buyer == contract.sender {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Eigenen Trade kann man nicht kaufen"
        }))).into_response();
    }

    // Time-Lock prüfen
    let now = chrono::Utc::now().timestamp();
    if now >= contract.time_lock {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "HTLC ist abgelaufen – Trade nicht mehr verfügbar"
        }))).into_response();
    }

    // Escrowed Preimage holen
    let preimage = {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        store.get_escrowed_preimage(&req.htlc_id).cloned()
    };

    let preimage = match preimage {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Kein gespeichertes Preimage – manueller Claim erforderlich"
        }))).into_response(),
    };

    // Preimage nochmal gegen Hash-Lock verifizieren
    if !stone::token::htlc::HtlcStore::verify_preimage(&contract.hash_lock, &preimage) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "ok": false, "error": "Gespeichertes Preimage ungültig – inkonsistenter Zustand"
        }))).into_response();
    }

    // Claim-TX bauen
    let memo = serde_json::to_string(&HtlcClaimParams {
        htlc_id: req.htlc_id.clone(),
        preimage: preimage.clone(),
    }).unwrap_or_default();

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::HtlcClaim,
        from: HTLC_ESCROW_POOL.to_string(),
        to: buyer.clone(),
        amount: contract.amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce: 0,
        timestamp: now,
        signature: "system".to_string(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);
    let tx_id = tx.tx_id.clone();

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            // Preimage aus Escrow entfernen
            {
                let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
                store.remove_escrowed_preimage(&req.htlc_id);
                if let Err(e) = store.persist() {
                    eprintln!("[htlc] ⚠️  Preimage-Cleanup persist fehlgeschlagen: {e}");
                }
            }

            if let Some(ref net) = state.network {
                let net = net.clone();
                let tx_clone = tx;
                tokio::spawn(async move { net.broadcast_tx(tx_clone).await; });
            }

            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "tx_id": tx_id,
                "htlc_id": req.htlc_id,
                "buyer": buyer,
                "amount": contract.amount.to_string(),
                "message": "Kauf erfolgreich – STONE werden im nächsten Block übertragen",
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Mempool: {e}")
        }))).into_response(),
    }
}

/// GET /api/v1/htlc/:htlc_id
///
/// Gibt Details eines HTLC-Contracts zurück.
pub async fn handle_htlc_get(
    State(state): State<AppState>,
    Path(htlc_id): Path<String>,
) -> impl IntoResponse {
    let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());

    match store.get(&htlc_id) {
        Some(contract) => (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "htlc": {
                "id": contract.id,
                "sender": contract.sender,
                "receiver": contract.receiver,
                "amount": contract.amount.to_string(),
                "hash_lock": contract.hash_lock,
                "time_lock": contract.time_lock,
                "status": format!("{:?}", contract.status),
                "created_at_block": contract.created_at_block,
                "settlement_tx": contract.settlement_tx,
                "price": contract.price,
            }
        }))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false, "error": "HTLC nicht gefunden"
        }))).into_response(),
    }
}

/// GET /api/v1/htlc/list?address=...
///
/// Listet alle HTLCs für eine Wallet-Adresse (als Sender oder Empfänger).
pub async fn handle_htlc_list(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let address = params.get("address").map(|s| s.as_str()).unwrap_or("");

    let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
    let all = store.list_all();

    let filtered: Vec<_> = if address.is_empty() {
        all.iter().map(|c| serde_json::json!({
            "id": c.id,
            "sender": c.sender,
            "receiver": c.receiver,
            "amount": c.amount.to_string(),
            "hash_lock": c.hash_lock,
            "time_lock": c.time_lock,
            "status": format!("{:?}", c.status),
            "created_at_block": c.created_at_block,
            "price": c.price,
        })).collect()
    } else {
        all.iter()
            .filter(|c| c.sender == address || c.receiver == address)
            .map(|c| serde_json::json!({
                "id": c.id,
                "sender": c.sender,
                "receiver": c.receiver,
                "amount": c.amount.to_string(),
                "hash_lock": c.hash_lock,
                "time_lock": c.time_lock,
                "status": format!("{:?}", c.status),
                "created_at_block": c.created_at_block,
                "price": c.price,
            }))
            .collect()
    };

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "htlcs": filtered,
        "count": filtered.len(),
    }))).into_response()
}

/// POST /api/v1/htlc/generate-preimage
///
/// Generiert ein zufälliges Preimage und gibt es mit dem zugehörigen Hash zurück.
/// Hilfsfunktion für die Client-Seite beim Erstellen eines HTLC.
pub async fn handle_htlc_generate_preimage() -> impl IntoResponse {
    let (preimage, hash) = stone::token::htlc::generate_preimage();
    Json(serde_json::json!({
        "ok": true,
        "preimage": preimage,
        "hash_lock": hash,
    }))
}

/// GET /api/v1/htlc/payment-info
///
/// Gibt die verfügbaren Payment-Chains, Assets und Safe-Adressen zurück.
/// Clients nutzen diese Info, um dem Käufer die Zahlungsanweisung anzuzeigen.
pub async fn handle_htlc_payment_info() -> impl IntoResponse {
    // Safe-Config aus node_config.json laden
    let cfg = load_bridge_safes_config();

    let mut chains = Vec::new();
    for (chain_name, info) in &cfg {
        let safe_addr = info.get("safe_address").and_then(|v| v.as_str()).unwrap_or("");
        let tokens: Vec<String> = info.get("tokens")
            .and_then(|v| v.as_object())
            .map(|t| t.keys().cloned().collect())
            .unwrap_or_default();

        chains.push(serde_json::json!({
            "chain": chain_name,
            "safe_address": safe_addr,
            "enabled": !safe_addr.is_empty(),
            "tokens": tokens,
        }));
    }

    Json(serde_json::json!({
        "ok": true,
        "supported_chains": stone::token::htlc::SUPPORTED_CHAINS,
        "supported_assets": stone::token::htlc::SUPPORTED_ASSETS,
        "chains": chains,
    }))
}

/// Hardcoded Bridge-Safe Konfiguration.
/// Sicherheit: Adressen im Code, nicht in Config-Dateien änderbar.
pub fn load_bridge_safes_config() -> serde_json::Map<String, serde_json::Value> {
    let cfg = serde_json::json!({
        "polygon": {
            "safe_address": "0x0759a5794D4FF506C2278019A207ac27E8ADA956",
            "rpc_url": "https://polygon-rpc.com",
            "safe_api": "https://safe-transaction-polygon.safe.global",
            "tokens": {
                "USDT": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
                "USDC": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"
            }
        },
        "ethereum": {
            "safe_address": "0x6A8C85540F0754eA03b34dA9E15a151Aa8e90165",
            "rpc_url": "https://eth-mainnet.g.alchemy.com/v2/demo",
            "safe_api": "https://safe-transaction-mainnet.safe.global",
            "tokens": {
                "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "DAI":  "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            }
        },
        "bsc": {
            "safe_address": "0x0637b3d494F93373a19860Bf106f03820eaABD8b",
            "rpc_url": "https://bsc-dataseed.binance.org",
            "safe_api": "https://safe-transaction-bsc.safe.global",
            "tokens": {
                "USDT": "0x55d398326f99059fF775485246999027B3197955",
                "USDC": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"
            }
        },
        "arbitrum": {
            "safe_address": "0xDA5930A6D8da4Fe55618f2E17c7C1E3DebCA0e6b",
            "rpc_url": "https://arb1.arbitrum.io/rpc",
            "safe_api": "https://safe-transaction-arbitrum.safe.global",
            "tokens": {
                "USDT": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
                "USDC": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
            }
        },
        "base": {
            "safe_address": "0xd983ECe14878DD7a290db18E9545e6789eBe311f",
            "rpc_url": "https://mainnet.base.org",
            "safe_api": "https://safe-transaction-base.safe.global",
            "tokens": {
                "USDC": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
            }
        }
    });
    cfg.as_object().unwrap().clone()
}

// ═══════════════════════════════════════════════════════════════════════════════
// ─── Bridge (Wrapped Token Bridge) ──────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/bridge/summary
///
/// Gibt eine Zusammenfassung der Bridge-Aktivität zurück.
pub async fn handle_bridge_summary(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let store = state.node.bridge_store.read().unwrap_or_else(|e| e.into_inner());
    let summary = store.summary();
    let supply: std::collections::HashMap<String, String> = summary.total_supply.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "total_supply": supply,
        "holder_count": summary.holder_count,
        "total_deposits": summary.total_deposits,
        "pending_deposits": summary.pending_deposits,
        "total_withdrawals": summary.total_withdrawals,
        "pending_withdrawals": summary.pending_withdrawals,
        "supported_assets": ["wUSDT", "wUSDC", "wBTC", "wETH"],
    }))
}

/// GET /api/v1/bridge/balances?address=...
///
/// Gibt die Wrapped-Token-Balances für eine Adresse zurück.
pub async fn handle_bridge_balances(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let address = match params.get("address") {
        Some(a) => match stone::token::normalize_address(a) {
            Some(h) if h.len() == 64 => h,
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false, "error": "Ungültige Adresse"
            }))).into_response(),
        },
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "address Parameter fehlt"
        }))).into_response(),
    };

    let store = state.node.bridge_store.read().unwrap_or_else(|e| e.into_inner());
    let balances = store.balances_for(&address);
    let bal_map: std::collections::HashMap<String, String> = balances.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "address": address,
        "balances": bal_map,
    }))).into_response()
}

#[derive(Deserialize)]
pub struct BridgeDepositRequest {
    pub address: String,
    pub asset: String,
    pub amount: String,
    pub external_tx_hash: String,
}

/// POST /api/v1/bridge/deposit
///
/// Erstellt einen neuen Bridge-Deposit (Testnet: automatische Bestätigung).
/// Auf dem Mainnet würde dies einen Pending-Deposit erstellen, der vom
/// Bridge-Operator nach Bestätigung auf der externen Chain geminted wird.
pub async fn handle_bridge_deposit(
    State(state): State<AppState>,
    Json(req): Json<BridgeDepositRequest>,
) -> impl IntoResponse {
    let address = match stone::token::normalize_address(&req.address) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültige Stone-Adresse"
        }))).into_response(),
    };

    let asset = match stone::token::WrappedAsset::parse(&req.asset) {
        Some(a) => a,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false,
            "error": format!("Ungültiges Asset: {}. Erlaubt: wUSDT, wUSDC, wBTC, wETH", req.asset),
        }))).into_response(),
    };

    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) if a > rust_decimal::Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiger Betrag"
        }))).into_response(),
    };

    if req.external_tx_hash.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "external_tx_hash darf nicht leer sein"
        }))).into_response();
    }

    let mut store = state.node.bridge_store.write().unwrap_or_else(|e| e.into_inner());

    let external_chain = asset.external_chain().to_string();
    let deposit = store.create_deposit(
        address.clone(),
        asset.clone(),
        amount,
        external_chain,
        req.external_tx_hash.clone(),
    );

    // Testnet: automatisch bestätigen
    let deposit_id = deposit.id.clone();
    match store.confirm_deposit(&deposit_id) {
        Ok(confirmed) => {
            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "deposit": {
                    "id": confirmed.id,
                    "address": confirmed.stone_address,
                    "asset": confirmed.asset.to_string(),
                    "amount": confirmed.amount.to_string(),
                    "external_chain": confirmed.external_chain,
                    "external_tx_hash": confirmed.external_tx_hash,
                    "status": "confirmed",
                    "created_at": confirmed.created_at,
                    "confirmed_at": confirmed.confirmed_at,
                },
                "message": format!("{} {} geminted an {}", amount, asset, &address[..12]),
            }))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "ok": false, "error": format!("Deposit-Bestätigung fehlgeschlagen: {e}")
            }))).into_response()
        }
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct BridgeWithdrawRequest {
    pub address: String,
    pub asset: String,
    pub amount: String,
    pub external_address: String,
    #[serde(default)]
    pub mnemonic: String,
}

/// POST /api/v1/bridge/withdraw
///
/// Verbrennt Wrapped Tokens und stellt einen Withdrawal-Request.
pub async fn handle_bridge_withdraw(
    State(state): State<AppState>,
    Json(req): Json<BridgeWithdrawRequest>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_bridge_withdraw")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_bridge_withdraw");
    let address = match stone::token::normalize_address(&req.address) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültige Stone-Adresse"
        }))).into_response(),
    };

    let asset = match stone::token::WrappedAsset::parse(&req.asset) {
        Some(a) => a,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false,
            "error": format!("Ungültiges Asset: {}", req.asset),
        }))).into_response(),
    };

    let amount: rust_decimal::Decimal = match req.amount.parse() {
        Ok(a) if a > rust_decimal::Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültiger Betrag"
        }))).into_response(),
    };

    if req.external_address.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "external_address darf nicht leer sein"
        }))).into_response();
    }

    let mut store = state.node.bridge_store.write().unwrap_or_else(|e| e.into_inner());

    match store.create_withdrawal(address, asset, amount, req.external_address.clone()) {
        Ok(wd) => {
            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "withdrawal": {
                    "id": wd.id,
                    "address": wd.stone_address,
                    "asset": wd.asset.to_string(),
                    "amount": wd.amount.to_string(),
                    "external_chain": wd.external_chain,
                    "external_address": wd.external_address,
                    "status": "pending",
                    "created_at": wd.created_at,
                },
                "message": format!("{} {} verbrannt, Withdrawal pending", wd.amount, wd.asset),
            }))).into_response()
        }
        Err(e) => {
            let status = match &e {
                stone::token::BridgeError::InsufficientBalance { .. } => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(serde_json::json!({
                "ok": false,
                "error": format!("{e}"),
            }))).into_response()
        }
    }
}

/// GET /api/v1/bridge/deposits?address=...
///
/// Listet alle Deposits für eine Adresse.
pub async fn handle_bridge_deposits(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let store = state.node.bridge_store.read().unwrap_or_else(|e| e.into_inner());

    let deposits = if let Some(addr) = params.get("address") {
        let addr = stone::token::normalize_address(addr).unwrap_or_default();
        store.deposits_for(&addr).into_iter().cloned().collect::<Vec<_>>()
    } else {
        store.all_deposits().to_vec()
    };

    let items: Vec<serde_json::Value> = deposits.iter().map(|d| {
        serde_json::json!({
            "id": d.id,
            "address": d.stone_address,
            "asset": d.asset.to_string(),
            "amount": d.amount.to_string(),
            "external_chain": d.external_chain,
            "external_tx_hash": d.external_tx_hash,
            "status": format!("{:?}", d.status),
            "created_at": d.created_at,
            "confirmed_at": d.confirmed_at,
        })
    }).collect();

    Json(serde_json::json!({
        "ok": true,
        "deposits": items,
        "count": items.len(),
    }))
}

/// GET /api/v1/bridge/withdrawals?address=...
///
/// Listet alle Withdrawals für eine Adresse.
pub async fn handle_bridge_withdrawals(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let store = state.node.bridge_store.read().unwrap_or_else(|e| e.into_inner());

    let withdrawals = if let Some(addr) = params.get("address") {
        let addr = stone::token::normalize_address(addr).unwrap_or_default();
        store.withdrawals_for(&addr).into_iter().cloned().collect::<Vec<_>>()
    } else {
        store.all_withdrawals().to_vec()
    };

    let items: Vec<serde_json::Value> = withdrawals.iter().map(|w| {
        serde_json::json!({
            "id": w.id,
            "address": w.stone_address,
            "asset": w.asset.to_string(),
            "amount": w.amount.to_string(),
            "external_chain": w.external_chain,
            "external_address": w.external_address,
            "status": format!("{:?}", w.status),
            "created_at": w.created_at,
            "completed_at": w.completed_at,
            "external_tx_hash": w.external_tx_hash,
        })
    }).collect();

    Json(serde_json::json!({
        "ok": true,
        "withdrawals": items,
        "count": items.len(),
    }))
}

// ─── HTLC Buy Init / Status (Zahlungsverifizierter Kauf) ────────────────────

#[derive(Deserialize)]
pub struct HtlcBuyInitRequest {
    pub htlc_id: String,
    pub buyer_wallet: String,
    /// Gewünschte Payment-Chain (z.B. "polygon")
    #[serde(default)]
    pub chain: Option<String>,
    /// Gewünschtes Payment-Asset (z.B. "USDT")
    #[serde(default)]
    pub asset: Option<String>,
}

/// POST /api/v1/htlc/buy/init
///
/// Initiiert einen Kaufvorgang mit Zahlungsverifizierung.
/// Gibt dem Käufer die Zahlungsanweisung (Safe-Adresse, Betrag, Asset, Chain).
/// Der Bridge Monitor beobachtet die Safe und claimed automatisch bei Zahlung.
pub async fn handle_htlc_buy_init(
    State(state): State<AppState>,
    Json(req): Json<HtlcBuyInitRequest>,
) -> impl IntoResponse {
    use stone::token::htlc::{BuyStatus, PendingBuy, SUPPORTED_CHAINS, SUPPORTED_ASSETS};

    // Käufer validieren
    let buyer = match stone::token::normalize_address(&req.buyer_wallet) {
        Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Ungültige buyer_wallet"
        }))).into_response(),
    };

    // HTLC laden
    let contract = {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        store.get(&req.htlc_id).cloned()
    };
    let contract = match contract {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false, "error": "HTLC nicht gefunden"
        }))).into_response(),
    };

    // Validierungen
    if contract.status != HtlcStatus::Locked {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "HTLC ist nicht aktiv"
        }))).into_response();
    }
    if !contract.receiver.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "HTLC hat bereits einen Empfänger"
        }))).into_response();
    }
    if buyer == contract.sender {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "Eigenen Trade kann man nicht kaufen"
        }))).into_response();
    }
    let now = chrono::Utc::now().timestamp();
    if now >= contract.time_lock {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "HTLC ist abgelaufen"
        }))).into_response();
    }

    // Preis muss gesetzt sein
    let price = match &contract.price {
        Some(p) => p.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "HTLC hat keinen Preis – normaler Kauf über /api/v1/htlc/buy verwenden"
        }))).into_response(),
    };

    // Chain/Asset: Entweder aus Request oder aus HTLC-Preis
    let chain = req.chain.as_deref().unwrap_or(&price.chain);
    let asset = req.asset.as_deref().unwrap_or(&price.asset);

    if !SUPPORTED_CHAINS.contains(&chain) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Unsupported chain: {chain}")
        }))).into_response();
    }
    if !SUPPORTED_ASSETS.contains(&asset) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Unsupported asset: {asset}")
        }))).into_response();
    }

    // Prüfen ob für diesen HTLC schon ein aktiver Buy existiert
    {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        if store.has_active_buy_for_htlc(&req.htlc_id) {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "ok": false, "error": "Für diesen HTLC läuft bereits ein Kaufvorgang"
            }))).into_response();
        }
    }

    // Safe-Adresse für die Chain laden
    let safes_config = load_bridge_safes_config();
    let chain_cfg = match safes_config.get(chain) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("Chain {chain} nicht konfiguriert")
        }))).into_response(),
    };
    let safe_address = match chain_cfg.get("safe_address").and_then(|v| v.as_str()) {
        Some(a) if !a.is_empty() => a.to_string(),
        _ => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "ok": false, "error": format!("Bridge-Safe für {chain} noch nicht eingerichtet")
        }))).into_response(),
    };

    // Escrowed Preimage prüfen
    {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        if store.get_escrowed_preimage(&req.htlc_id).is_none() {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "ok": false, "error": "Kein Preimage vorhanden – manueller Kauf nötig"
            }))).into_response();
        }
    }

    // PendingBuy erstellen
    let buy_id = format!("buy-{:016x}", rand::random::<u64>());
    // Buy-Timeout: Minimum von 30 Minuten und HTLC time_lock
    let buy_expires = std::cmp::min(now + 1800, contract.time_lock - 120);
    if buy_expires <= now {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "HTLC läuft zu bald ab für verifiziertes Kaufen"
        }))).into_response();
    }

    let pending = PendingBuy {
        buy_id: buy_id.clone(),
        htlc_id: req.htlc_id.clone(),
        buyer: buyer.clone(),
        expected_amount: price.amount.clone(),
        expected_asset: asset.to_string(),
        expected_chain: chain.to_string(),
        safe_address: safe_address.clone(),
        status: BuyStatus::WaitingForPayment,
        created_at: now,
        expires_at: buy_expires,
        payment_tx_hash: None,
        claim_tx_id: None,
    };

    {
        let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
        store.create_pending_buy(pending);
        if let Err(e) = store.persist() {
            eprintln!("[htlc] ⚠️  PendingBuy persist fehlgeschlagen: {e}");
        }
    }

    println!("[htlc] 🛒 Buy initiiert: {} → HTLC {} ({} {} auf {})",
        buy_id, req.htlc_id, price.amount, asset, chain);

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "buy_id": buy_id,
        "htlc_id": req.htlc_id,
        "status": "WaitingForPayment",
        "payment": {
            "safe_address": safe_address,
            "amount": price.amount,
            "asset": asset,
            "chain": chain,
            "expires_at": buy_expires,
        },
        "stone_amount": contract.amount.to_string(),
        "message": format!("Sende {} {} an {} auf {}", price.amount, asset, safe_address, chain),
    }))).into_response()
}

/// GET /api/v1/htlc/buy/status?buy_id=...
///
/// Gibt den aktuellen Status eines Kaufvorgangs zurück.
pub async fn handle_htlc_buy_status(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let buy_id = match params.get("buy_id") {
        Some(id) if !id.is_empty() => id,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": "buy_id Parameter fehlt"
        }))).into_response(),
    };

    let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
    match store.get_pending_buy(buy_id) {
        Some(buy) => {
            let status_str = match &buy.status {
                BuyStatus::WaitingForPayment => "WaitingForPayment",
                BuyStatus::PaymentDetected => "PaymentDetected",
                BuyStatus::PaymentConfirmed => "PaymentConfirmed",
                BuyStatus::Completed => "Completed",
                BuyStatus::Expired => "Expired",
                BuyStatus::Failed(_) => "Failed",
            };
            let error_msg = match &buy.status {
                BuyStatus::Failed(msg) => Some(msg.clone()),
                _ => None,
            };

            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "buy_id": buy.buy_id,
                "htlc_id": buy.htlc_id,
                "status": status_str,
                "payment": {
                    "safe_address": buy.safe_address,
                    "amount": buy.expected_amount,
                    "asset": buy.expected_asset,
                    "chain": buy.expected_chain,
                    "expires_at": buy.expires_at,
                },
                "payment_tx_hash": buy.payment_tx_hash,
                "claim_tx_id": buy.claim_tx_id,
                "error": error_msg,
            }))).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false, "error": "Kaufvorgang nicht gefunden"
        }))).into_response(),
    }
}