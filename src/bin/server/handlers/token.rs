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
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use stone::token::{
    AccountInfo, SupplyInfo, TokenTx, TxType,
};

use super::super::state::AppState;

// ─── Supply Info ─────────────────────────────────────────────────────────────

/// GET /api/v1/token/supply
pub async fn handle_token_supply(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap();
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
    let ledger = state.node.token_ledger.read().unwrap();
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
    let ledger = state.node.token_ledger.read().unwrap();
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

/// GET /api/v1/token/accounts
pub async fn handle_token_accounts(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap();
    let accounts = ledger.all_accounts();
    Json(serde_json::json!({
        "ok": true,
        "count": accounts.len(),
        "accounts": accounts,
    }))
}

// ─── Pending TXs ────────────────────────────────────────────────────────────

/// GET /api/v1/token/pending
pub async fn handle_token_pending(
    State(state): State<AppState>,
) -> impl IntoResponse {
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

    Json(serde_json::json!({
        "ok": true,
        "count": items.len(),
        "pending": items,
    }))
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

    // Nur Transfers, Burns, Key-Rotations, Stake und Unstake erlauben (Mint/Reward kommen nur vom System)
    if tx.tx_type != TxType::Transfer && tx.tx_type != TxType::Burn && tx.tx_type != TxType::RotateKey
        && tx.tx_type != TxType::Stake && tx.tx_type != TxType::Unstake
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Nur Transfer-, Burn-, RotateKey-, Stake- und Unstake-Transaktionen können eingereicht werden",
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
        let ledger = state.node.token_ledger.read().unwrap();
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
        let ledger = state.node.token_ledger.read().unwrap();
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
        let ledger = state.node.token_ledger.read().unwrap();
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

    // Direkt im Ledger: Transfer von Community-Pool → Empfänger
    let result = {
        let mut ledger = state.node.token_ledger.write().unwrap();
        let available = ledger.balance(pool);
        if available < amount {
            Err(format!("Community-Pool hat nur {} STONE verfügbar", available))
        } else {
            ledger.transfer(pool, &req.address, amount, rust_decimal::Decimal::ZERO)
                .map_err(|e| format!("{e}"))
                .and_then(|_| {
                    ledger.persist().map_err(|e| format!("{e}"))?;
                    Ok(())
                })
        }
    };

    match result {
        Ok(()) => {
            let ledger = state.node.token_ledger.read().unwrap();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "amount": FAUCET_AMOUNT,
                    "to": req.address,
                    "new_balance": ledger.balance(&req.address).to_string(),
                    "pool_remaining": ledger.balance(pool).to_string(),
                })),
            )
        }
        Err(e) => {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": e,
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
    let chain = state.node.chain.lock().unwrap();

    let mut txs: Vec<serde_json::Value> = Vec::new();
    for block in &chain.blocks {
        for tx in &block.transactions {
            if tx.from == address || tx.to == address {
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
                }));
            }
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "address": address,
        "count": txs.len(),
        "transactions": txs,
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
    let ledger = state.node.token_ledger.read().unwrap();

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
    pub mnemonic: String,
    /// Empfänger-Adresse (Public-Key-Hex, 64 Zeichen)
    pub to: String,
    /// Betrag in STONE
    pub amount: String,
    /// Absender-Adresse zur Validierung (muss mit Mnemonic übereinstimmen)
    #[serde(default)]
    pub from: String,
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

    // Empfänger-Adresse validieren
    if req.to.len() != 64 || !req.to.chars().all(|c| c.is_ascii_hexdigit()) {
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

    // Nonce aus dem Ledger holen
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap();
        ledger.nonce(&wallet.address())
    };

    // TX signieren
    let tx = match wallet.sign_tx(
        TxType::Transfer,
        req.to.clone(),
        amount,
        rust_decimal::Decimal::ZERO, // keine Fee aktuell
        nonce,
        String::new(),
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
        let ledger = state.node.token_ledger.read().unwrap();
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
                    "message": "TX im Mempool – wird beim nächsten Block-Commit verarbeitet",
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

// ─── Staking API-Handler ─────────────────────────────────────────────────────

/// POST /api/v1/token/stake
///
/// Nimmt eine bereits signierte Stake-TX entgegen und schiebt sie in den Mempool.
pub async fn handle_token_stake(
    State(state): State<AppState>,
    Json(req): Json<TransferRequest>,
) -> impl IntoResponse {
    let tx = req.tx;

    if tx.tx_type != TxType::Stake {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "TX-Typ muss 'Stake' sein",
            })),
        );
    }

    // In Mempool aufnehmen
    let result = {
        let ledger = state.node.token_ledger.read().unwrap();
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
                    "amount": tx.amount.to_string(),
                    "message": "Stake-TX im Mempool – wird beim nächsten Block verarbeitet",
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /api/v1/token/unstake
///
/// Nimmt eine bereits signierte Unstake-TX entgegen und schiebt sie in den Mempool.
pub async fn handle_token_unstake(
    State(state): State<AppState>,
    Json(req): Json<TransferRequest>,
) -> impl IntoResponse {
    let tx = req.tx;

    if tx.tx_type != TxType::Unstake {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "TX-Typ muss 'Unstake' sein",
            })),
        );
    }

    let result = {
        let ledger = state.node.token_ledger.read().unwrap();
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
                    "amount": tx.amount.to_string(),
                    "lock_period_days": 7,
                    "message": "Unstake-TX im Mempool – 7 Tage Lock-Periode nach Verarbeitung",
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /api/v1/staking/info
///
/// Öffentliche Staking-Pool-Übersicht: Gesamt-Stake, APY, Epoch, etc.
pub async fn handle_staking_info(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let pool = state.node.staking_pool.read().unwrap();
    let reward_pool_balance = {
        let ledger = state.node.token_ledger.read().unwrap();
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
    let pool = state.node.staking_pool.read().unwrap();
    let reward_pool_balance = {
        let ledger = state.node.token_ledger.read().unwrap();
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
    let pool = state.node.staking_pool.read().unwrap();

    match pool.staker_info(&address) {
        Some(info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "staker": info,
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": "Adresse hat keinen aktiven Stake",
            })),
        ),
    }
}