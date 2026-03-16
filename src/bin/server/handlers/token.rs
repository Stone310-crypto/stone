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
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;

use stone::token::{
    AccountInfo, SupplyInfo, TokenTx, TxType, compute_tx_id, default_chain_id,
    TokenLedger,
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
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let balance = ledger.balance(&address);
    let nonce = ledger.nonce(&address);
    Json(serde_json::json!({
        "ok": true,
        "address": address,
        "balance": balance.to_string(),
        "nonce": nonce,
    }))
}

/// GET /api/v1/wallet/:address
pub async fn handle_wallet_info(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let info = AccountInfo {
        address: address.clone(),
        balance: ledger.balance(&address),
        nonce: ledger.nonce(&address),
    };
    Json(serde_json::json!({
        "ok": true,
        "account": info,
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

    // Adress-Validierung: genau 64 Hex-Zeichen, kein Pool-Prefix
    if req.address.len() != 64
        || !req.address.chars().all(|c| c.is_ascii_hexdigit())
        || req.address.starts_with("pool:")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Adresse: muss 64 Hex-Zeichen sein (Ed25519 Public Key)",
            })),
        );
    }

    // Rate Limiting: per Empfänger-Adresse
    if !state.rate_limits.faucet.check(&req.address) {
        let retry = state.rate_limits.faucet.retry_after_secs(&req.address);
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
        let current_balance = ledger.balance(&req.address);
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

    // ── Mint-TX erstellen (wird durch Mempool + P2P gesynct) ──
    // Pool-Balance prüfen
    {
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
    }

    // Nonce aus Ledger holen + pending TXs (pool:community)
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let base = ledger.nonce(pool);
        base + state.node.mempool.sender_pending_count(pool)
    };

    // TokenTx mit TxType::Transfer erstellen – Pool-Signatur wird übersprungen
    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: pool.to_string(),
        to: req.address.clone(),
        amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: "system-faucet".to_string(),
        memo: "Testnet Faucet".to_string(),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
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
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let chain_height = chain.blocks.len() as u64;

    let mut txs: Vec<serde_json::Value> = Vec::new();
    for block in &chain.blocks {
        for tx in &block.transactions {
            if tx.from == address || tx.to == address {
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
        "address": address,
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

    // Empfänger-Adresse validieren
    if req.to.is_empty() || req.to.len() != 64 || !req.to.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Empfänger-Adresse: muss 64 Hex-Zeichen sein",
            })),
        );
    }

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

    // Optional: from-Adresse gegen Wallet-Adresse prüfen
    if !req.from.is_empty() && req.from != wallet.address() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Absender-Adresse stimmt nicht mit dem Mnemonic überein. Falscher Mnemonic?",
            })),
        );
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
        Some("express")  => stone::token::FeeTier::Express,
        Some("priority") => stone::token::FeeTier::Priority,
        Some("standard") | None => stone::token::FeeTier::Standard,
        Some(other) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Unbekannter fee_tier: '{}'. Erlaubt: express, priority, standard", other),
            })),
        ),
    };

    // TX signieren mit Fee-Tier
    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer,
        req.to.clone(),
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
                        stone::token::FeeTier::Express  => "Express-TX im Mempool – wird im nächsten Block verarbeitet",
                        stone::token::FeeTier::Priority => "Priority-TX im Mempool – wird innerhalb von ~5 Minuten verarbeitet",
                        stone::token::FeeTier::Standard => "Standard-TX im Mempool – wird beim nächsten Dokument-Upload verarbeitet (kostenlos)",
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
/// Body: { "to": "...", "amount": "10", "fee_tier": "express", "mnemonic": "..." }
pub async fn handle_token_send_authenticated(
    State(state): State<AppState>,
    Json(req): Json<SendAuthenticatedRequest>,
) -> impl IntoResponse {
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

    // Empfänger validieren
    if req.to.is_empty() || req.to.len() != 64 || !req.to.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Empfänger-Adresse: muss 64 Hex-Zeichen sein",
            })),
        );
    }

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
        "express"  => stone::token::FeeTier::Express,
        "priority" => stone::token::FeeTier::Priority,
        "standard" => stone::token::FeeTier::Standard,
        other => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Unbekannter fee_tier: '{}'. Erlaubt: express, priority, standard", other),
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
        req.to.clone(),
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
                        stone::token::FeeTier::Express  => "Express-TX – wird im nächsten Block verarbeitet",
                        stone::token::FeeTier::Priority => "Priority-TX – wird innerhalb von ~5 Minuten verarbeitet",
                        stone::token::FeeTier::Standard => "Standard-TX – wird beim nächsten Dokument-Upload verarbeitet (kostenlos)",
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
        ledger.balance("pool:storage_rewards")
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
        ledger.balance("pool:storage_rewards")
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
    let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());

    match pool.staker_info(&address) {
        Some(info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "staker": info,
            })),
        ),
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "staker": {
                    "address": address,
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

    // Adress-Validierung
    if req.to.len() != 64 || !req.to.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Ungültige Empfänger-Adresse: muss 64 Hex-Zeichen sein",
            })),
        ).into_response();
    }

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
        to: req.to.clone(),
        amount,
        fee: rust_decimal::Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: "admin-airdrop".to_string(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
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