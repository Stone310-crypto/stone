//! Stone SDK – API Handler
//!
//! Alle Endpunkte für das Gaming-SDK:
//!
//! - Developer:  /api/v1/sdk/register, /api/v1/sdk/game/*
//! - Consent:    /api/v1/sdk/consent/*
//! - Wallet:     /api/v1/sdk/wallet/*
//! - TX:         /api/v1/sdk/tx/*
//! - Market:     /api/v1/sdk/market/*
//! - Game:       /api/v1/sdk/game/*
//! - Auth:       /api/v1/sdk/auth/*
//! - Player:     /api/v1/sdk/player/*

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use stone::token::{
    TokenTx, TxType, Wallet, compute_tx_id, default_chain_id,
    game_economy::{
        GameEconomyStore, GamePermission, MARKETPLACE_POOL, MAX_BATCH_SIZE,
        GameGenre, derive_game_wallet,
    },
};

use super::super::state::AppState;

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn read_game_store(state: &AppState) -> GameEconomyStore {
    state.node.game_economy.read().unwrap_or_else(|e| e.into_inner()).clone()
}

fn with_game_store_mut<F, R>(state: &AppState, f: F) -> R
where
    F: FnOnce(&mut GameEconomyStore) -> R,
{
    let mut store = state.node.game_economy.write().unwrap_or_else(|e| e.into_inner());
    let result = f(&mut store);
    if let Err(e) = store.persist() {
        eprintln!("[sdk-api] ⚠️  Persist fehlgeschlagen: {e}");
    }
    result
}

fn err_json(msg: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": false, "error": msg }))
}

fn ok_json(data: serde_json::Value) -> Json<serde_json::Value> {
    let mut obj = data;
    obj.as_object_mut().map(|m| m.insert("ok".into(), serde_json::json!(true)));
    Json(obj)
}

/// TX über P2P broadcasten (fire-and-forget).
fn broadcast_tx(state: &AppState, tx: TokenTx) {
    if let Some(ref net) = state.network {
        let net = net.clone();
        tokio::spawn(async move { net.broadcast_tx(tx).await; });
    }
}

/// Validiert den SDK-Key (Klartext oder Hash) und gibt die game_id zurück.
///
/// **Security**: Akzeptiert `X-SDK-Key-Hash` (SHA-256 des Keys, empfohlen)
/// oder `X-SDK-Key`/`X-API-Key` (Legacy, Klartext). Der Hash-Modus verhindert
/// MITM-Angriffe und schützt den Key vor Transient-Memory/Log-Exfiltration.
fn validate_sdk_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let store = read_game_store(state);

    // 1) Hash-basierte Auth (Security-Fix: kein Klartext-Key über die Leitung)
    if let Some(key_hash) = headers
        .get("X-SDK-Key-Hash")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return match store.validate_api_key_hash(key_hash) {
            Ok(game) => Ok(game.game_id.clone()),
            Err(e) => Err((StatusCode::FORBIDDEN, err_json(&e.to_string()))),
        };
    }

    // 2) Legacy: Klartext-Key (deprecated, wird in Zukunft entfernt)
    let key = headers
        .get("X-SDK-Key")
        .or_else(|| headers.get("X-API-Key"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                err_json("SDK-Key Header fehlt (erwartet: X-SDK-Key-Hash, X-SDK-Key oder X-API-Key)"),
            )
        })?;

    match store.validate_api_key(key) {
        Ok(game) => Ok(game.game_id.clone()),
        Err(e) => Err((StatusCode::FORBIDDEN, err_json(&e.to_string()))),
    }
}

/// Leitet die Wallet-Adresse eines Spielers ab — entweder aus signaturbasiertem
/// Ownership-Proof (empfohlen) oder aus dem Mnemonic (Legacy / Deprecated).
///
/// **Sicherer Pfad** (`pubkey` + `signature` gesetzt):
///   1. Signatur wird über `message_bytes` mit dem Public-Key geprüft
///   2. Aus dem Public-Key wird die Stone-Adresse abgeleitet
///   → Der private Key verlässt niemals den Client.
///
/// **Legacy-Pfad** (`mnemonic` gesetzt + `allow_mnemonic` true):
///   1. Wallet wird serverseitig aus dem Mnemonic rekonstruiert
///   2. Warnung wird geloggt
///   → Nur für CLI/Test-Workflows. Sollte in Produktion nicht genutzt werden.
fn derive_player_address(
    pubkey: Option<&str>,
    signature: Option<&str>,
    message_bytes: &[u8],
    mnemonic: Option<&str>,
    allow_mnemonic: bool,
    operation: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    // Bevorzugt: Signatur-basierter Ownership-Proof
    if let (Some(pk), Some(sig)) = (pubkey, signature) {
        let pk = pk.trim();
        let sig = sig.trim();
        if pk.is_empty() || sig.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                err_json("player_pubkey/signature dürfen nicht leer sein"),
            ));
        }
        // Public-Key normalisieren (Hex oder Bech32m)
        let pubkey_hex = match stone::token::normalize_address(pk) {
            Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
            _ => return Err((
                StatusCode::BAD_REQUEST,
                err_json("player_pubkey: ungültige Adresse (64-Hex oder stone1...)"),
            )),
        };
        // Ed25519-Signatur prüfen
        if let Err(e) = stone::crypto::verify_message_signature(&pubkey_hex, message_bytes, sig) {
            return Err((
                StatusCode::UNAUTHORIZED,
                err_json(&format!("Signatur-Verifikation fehlgeschlagen: {e}")),
            ));
        }
        return Ok(pubkey_hex);
    }

    // Legacy: Mnemonic — nur mit explizitem Opt-in
    if let Some(m) = mnemonic {
        if !m.trim().is_empty() {
            if !allow_mnemonic {
                return Err((
                    StatusCode::BAD_REQUEST,
                    err_json(
                        "Mnemonic-basierte Auth ist deprecated. Sende `player_pubkey` + \
                         `signature` (Ed25519, Hex) über die Operation. Für lokale Tests: \
                         `allow_mnemonic_auth: true` setzen.",
                    ),
                ));
            }
            eprintln!(
                "[sdk][WARN] {operation}: Mnemonic-Auth genutzt — der Seed wurde über HTTP \
                 übertragen. Migriere auf signaturbasierte Auth."
            );
            let wallet = Wallet::from_mnemonic(m).map_err(|e| (
                StatusCode::BAD_REQUEST,
                err_json(&format!("Mnemonic: {e}")),
            ))?;
            return Ok(wallet.address());
        }
    }

    Err((
        StatusCode::BAD_REQUEST,
        err_json(
            "Kein Ownership-Proof übergeben. Sende `player_pubkey` + `signature` \
             (Ed25519 über die Operations-Message).",
        ),
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §1 DEVELOPER – Spiel-Registrierung
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/quick-register ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct QuickRegisterReq {
    pub game_id: String,
    pub name: String,
    pub description: Option<String>,
    pub website: Option<String>,
    #[serde(default)]
    pub max_daily_limit: Option<String>,
    #[serde(default)]
    pub permissions: Option<Vec<GamePermission>>,
    #[serde(default)]
    pub genres: Option<Vec<GameGenre>>,

    /// **EMPFOHLEN**: Vom Client lokal generierter Public-Key (Hex oder `stone1...`).
    ///
    /// Wenn gesetzt, generiert der Server KEIN Wallet und der Mnemonic verlässt
    /// niemals den Client. Das ist der einzig sichere Modus für Produktion.
    ///
    /// Wenn `None`, wird das Server-Side-Generation-Fallback aktiviert
    /// (Mnemonic im Response → nur für lokale Entwicklung/Tests).
    #[serde(default)]
    pub developer_pubkey: Option<String>,

    /// Wenn `true` und `developer_pubkey` ist `None`, gibt der Server das
    /// generierte Mnemonic im Response zurück. **DEPRECATED** — nur für
    /// CLI/Test-Workflows. Default = `false` → Request schlägt fehl ohne pubkey.
    #[serde(default)]
    pub allow_server_side_wallet: bool,
}

/// POST /api/v1/sdk/quick-register – Spiel registrieren.
///
/// **Sicherer Modus (empfohlen)**: Client generiert Wallet lokal und sendet
/// nur `developer_pubkey` (Hex oder Bech32m). Server registriert das Spiel zu
/// dieser Adresse. Der Mnemonic verlässt niemals den Client.
///
/// **Legacy-Modus (deprecated)**: `allow_server_side_wallet: true` setzen.
/// Dann generiert der Server ein Wallet und gibt den Mnemonic im Response
/// zurück. **Nur für CLI/Test-Workflows** — niemals über öffentliche Netze
/// nutzen, da der Mnemonic in HTTP-Logs, Proxies und Browser-DevTools landet.
pub async fn handle_sdk_quick_register(
    State(state): State<AppState>,
    Json(req): Json<QuickRegisterReq>,
) -> impl IntoResponse {
    // 1. Developer-Adresse bestimmen: Client-Pubkey ODER Server-generiertes Wallet
    let (developer_addr, generated_wallet): (String, Option<Wallet>) = match &req.developer_pubkey {
        Some(pk) if !pk.trim().is_empty() => {
            // Sicherer Modus: Client hat lokal generiert und sendet nur Public-Key.
            let normalized = match stone::token::normalize_address(pk.trim()) {
                Some(h) if h.len() == 64 && !h.starts_with("pool:") => h,
                _ => return (
                    StatusCode::BAD_REQUEST,
                    err_json("developer_pubkey: ungültige Adresse (erwartet 64-Hex oder stone1...)"),
                ).into_response(),
            };
            (normalized, None)
        }
        _ => {
            // Legacy-Modus: nur erlaubt wenn explizit angefordert.
            if !req.allow_server_side_wallet {
                return (
                    StatusCode::BAD_REQUEST,
                    err_json(
                        "Kein `developer_pubkey` übergeben. Generiere das Wallet \
                         lokal (z.B. via Stone-SDK) und sende den Public-Key. \
                         Server-seitige Wallet-Generierung ist aus Sicherheitsgründen \
                         standardmäßig deaktiviert. Für lokale CLI-Tests: \
                         `allow_server_side_wallet: true` setzen."
                    ),
                ).into_response();
            }
            eprintln!(
                "[sdk][WARN] quick-register im Legacy-Modus aufgerufen: Server generiert Wallet, \
                 Mnemonic wird im HTTP-Response zurückgegeben. NIE über öffentliche Netze nutzen."
            );
            let wallet = match Wallet::generate() {
                Ok(w) => w,
                Err(e) => return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    err_json(&format!("Wallet-Generierung fehlgeschlagen: {e}")),
                ).into_response(),
            };
            (wallet.address(), Some(wallet))
        }
    };

    // 2. Defaults setzen
    let description = req.description.unwrap_or_default();
    let website = req.website.unwrap_or_default();
    let max_limit: Decimal = req.max_daily_limit
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Decimal::new(1000, 0));
        let permissions = req.permissions.unwrap_or_else(|| vec![
        GamePermission::Basic,
        GamePermission::Marketplace,
        GamePermission::Assets,
        GamePermission::Tournament, // Play-Drop erfordert Tournament
    ]);
    let genres = req.genres.unwrap_or_else(|| vec![GameGenre::Custom]);

    if max_limit <= Decimal::ZERO {
        return (StatusCode::BAD_REQUEST, err_json("max_daily_limit muss > 0 sein")).into_response();
    }

    // 3. Spiel registrieren
    let result = with_game_store_mut(&state, |store| {
        store.register_game(
            &req.game_id, &req.name, &description, &website,
            &developer_addr, max_limit, permissions.clone(), genres.clone(),
        )
    });

    match result {
        Ok((game, api_key)) => {
            let mut resp = serde_json::json!({
                "ok": true,
                "game_id": game.game_id,
                "developer_wallet": developer_addr,
                "api_key": api_key,
                "permissions": game.permissions,
                "genres": game.genres,
                "max_daily_limit": game.max_wallet_limit.to_string(),
                "client_side_wallet": generated_wallet.is_none(),
            });
            if let Some(w) = generated_wallet {
                // Legacy-Pfad: Mnemonic einmalig zurückgeben + deutliche Warnung.
                resp["mnemonic"] = serde_json::Value::String(w.mnemonic().to_string());
                resp["warning"] = serde_json::Value::String(
                    "⚠️ Mnemonic wurde serverseitig generiert und über HTTP übertragen. \
                     Für Produktion: Wallet lokal generieren und `developer_pubkey` senden.".into()
                );
                resp["note"] = serde_json::Value::String(
                    "Mnemonic + API-Key NUR JETZT sichtbar! Sicher aufbewahren!".into()
                );
            }
            Json(resp).into_response()
        }
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/register ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterGameReq {
    pub mnemonic: String,
    pub game_id: String,
    pub name: String,
    pub description: String,
    pub website: String,
    pub max_wallet_limit: String,
    pub permissions: Vec<GamePermission>,
    #[serde(default)]
    pub genres: Option<Vec<GameGenre>>,
}

/// POST /api/v1/sdk/register – Neues Spiel registrieren, API-Key erhalten
pub async fn handle_sdk_register(
    State(state): State<AppState>,
    Json(req): Json<RegisterGameReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_register")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_register");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let max_limit: Decimal = match req.max_wallet_limit.parse() {
        Ok(d) if d > Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges max_wallet_limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        let genres = req.genres.clone().unwrap_or_else(|| vec![GameGenre::Custom]);
        store.register_game(
            &req.game_id, &req.name, &req.description, &req.website,
            &wallet.address(), max_limit, req.permissions.clone(), genres,
        )
    });

    match result {
        Ok((game, api_key)) => Json(serde_json::json!({
            "ok": true,
            "game_id": game.game_id,
            "api_key": api_key,
            "note": "API-Key wird nur EINMAL angezeigt! Sicher aufbewahren.",
            "permissions": game.permissions,
            "genres": game.genres,
            "max_wallet_limit": game.max_wallet_limit.to_string(),
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/claim ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ClaimGameReq {
    /// Mnemonic des on-chain Owner-Wallets (= `OnChainGame.owner_company`).
    pub mnemonic: String,
    /// Bereits on-chain registrierte Game-ID (via `TxType::GameRegister`).
    pub game_id: String,
    /// Optional. Default: 1000.
    #[serde(default)]
    pub max_wallet_limit: Option<String>,
    /// Optional. Default: [Basic, Marketplace, Assets].
    #[serde(default)]
    pub permissions: Option<Vec<GamePermission>>,
    #[serde(default)]
    pub genres: Option<Vec<GameGenre>>,
}

/// POST /api/v1/sdk/claim – Bestehendes on-chain Spiel in den SDK-Store adoptieren.
///
/// Voraussetzung: `game_id` ist bereits via `TxType::GameRegister` on-chain
/// registriert. Der Aufrufer muss mit dem Mnemonic des `owner_company`-Wallets
/// signieren. Es wird ein neuer SDK-Eintrag inkl. API-Key erstellt — so kann
/// dasselbe Spiel sowohl on-chain (zensur-resistent) als auch über SDK
/// (Drop/Shop/Marketplace) genutzt werden, **mit identischer game_id**.
pub async fn handle_sdk_claim(
    State(state): State<AppState>,
    Json(req): Json<ClaimGameReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_claim")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_claim");

    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };
    let claimant_addr = wallet.address();

    // 1. On-Chain Game laden + Owner verifizieren.
    let (onchain_name, onchain_owner) = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        match ledger.game(&req.game_id) {
            Some(g) => (g.name.clone(), g.owner_company.clone()),
            None => return (StatusCode::NOT_FOUND, err_json(&format!(
                "Spiel '{}' ist nicht on-chain registriert. \
                 Erst via TxType::GameRegister registrieren (z.B. über StoneScan).",
                req.game_id
            ))).into_response(),
        }
    };
    if onchain_owner != claimant_addr {
        return (StatusCode::FORBIDDEN, err_json(&format!(
            "Wallet {claimant_addr} ist nicht der on-chain Owner von '{}' \
             (erwartet: {onchain_owner}).",
            req.game_id
        ))).into_response();
    }

    // 2. Limits + Permissions auflösen.
    let max_limit: Decimal = req.max_wallet_limit
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Decimal::new(1000, 0));
    if max_limit <= Decimal::ZERO {
        return (StatusCode::BAD_REQUEST, err_json("max_wallet_limit muss > 0 sein")).into_response();
    }
    let permissions = req.permissions.unwrap_or_else(|| vec![
        GamePermission::Basic, GamePermission::Marketplace, GamePermission::Assets,
    ]);
    let genres = req.genres.unwrap_or_else(|| vec![GameGenre::Custom]);

    // 3. SDK-Eintrag anlegen (idempotent prüfen: 409, wenn schon geclaimt).
    let result = with_game_store_mut(&state, |store| {
        if store.get_game(&req.game_id).is_some() {
            return Err(stone::token::game_economy::GameEconomyError::AlreadyExists {
                what: format!("SDK-Eintrag für '{}' (bereits geclaimt)", req.game_id),
            });
        }
        store.register_game(
            &req.game_id,
            &onchain_name,
            "Claimed from on-chain GameRegister",
            "",
            &claimant_addr,
            max_limit,
            permissions.clone(),
            genres,
        )
    });

    match result {
        Ok((game, api_key)) => Json(serde_json::json!({
            "ok": true,
            "game_id": game.game_id,
            "name": game.name,
            "developer_wallet": claimant_addr,
            "api_key": api_key,
            "note": "API-Key wird nur EINMAL angezeigt! Sicher aufbewahren.",
            "permissions": game.permissions,
            "genres": game.genres,
            "max_wallet_limit": game.max_wallet_limit.to_string(),
            "source": "claimed_from_onchain",
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Owner-Sig-Challenge (Discord-Bot-Token-Style 2FA via Ed25519-Wallet-Signatur)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Flow:
//    1. Client → POST /api/v1/sdk/owner/challenge { game_id, action }
//       Server validiert Game existiert, generiert 32-Byte Nonce, bindet ihn an
//       (game_id, action, owner_wallet) und gibt `canonical_message` zurück.
//    2. Client signiert `canonical_message` mit dem Ed25519-Schlüssel des
//       developer_wallet (lokal, z.B. aus Mnemonic abgeleitet).
//    3. Client → POST /api/v1/sdk/owner/api-key/rotate { game_id, signature }
//       Server konsumiert die Challenge, verifiziert die Signatur gegen
//       developer_wallet, führt die Aktion aus und gibt das Ergebnis zurück.
//
//  Replay-Schutz: Nonce ist 32 Byte zufällig, TTL 300s, single-use.
//  Action-Binding: canonical_message enthält action+game_id+expires_at →
//                  Signatur kann nicht für eine andere Aktion missbraucht werden.

use std::sync::OnceLock;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use data_encoding::BASE32_NOPAD;

const OWNER_CHALLENGE_TTL_SECS: u64 = 300;

#[derive(Clone, Debug)]
struct OwnerChallenge {
    game_id: String,
    action: String,
    owner_wallet: String,
    canonical_message: String,
    expires_at: u64,
}

fn owner_challenges() -> &'static Mutex<HashMap<String, OwnerChallenge>> {
    static STORE: OnceLock<Mutex<HashMap<String, OwnerChallenge>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Erlaubte Owner-Actions. Erweiterbar (transfer_ownership, suspend, …).
const ALLOWED_OWNER_ACTIONS: &[&str] = &[
    "rotate_api_key",
    "suspend_game",
    "transfer_ownership",
    "add_server_key",
    "setup_totp",
    "configure_gaming_pool",
    "delete_gaming_pool",
];

const TOTP_STEP_SECS: u64 = 30;
const TOTP_DIGITS: u32 = 6;

fn generate_totp_secret_b32() -> String {
    let mut raw = [0u8; 20];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut raw);
    BASE32_NOPAD.encode(&raw)
}

fn totp_code_at(secret: &[u8], step: u64) -> u32 {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret).expect("hmac key");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin_code = ((u32::from(digest[offset] & 0x7f)) << 24)
        | ((u32::from(digest[offset + 1])) << 16)
        | ((u32::from(digest[offset + 2])) << 8)
        | u32::from(digest[offset + 3]);
    bin_code % 10u32.pow(TOTP_DIGITS)
}

fn verify_totp_code(secret_b32: &str, code: &str) -> bool {
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Ok(code_num) = code.parse::<u32>() else {
        return false;
    };
    let Ok(secret) = BASE32_NOPAD.decode(secret_b32.as_bytes()) else {
        return false;
    };
    let now_step = now_secs() / TOTP_STEP_SECS;
    for delta in [-1_i64, 0, 1] {
        let step = if delta.is_negative() {
            now_step.saturating_sub(delta.unsigned_abs())
        } else {
            now_step.saturating_add(delta as u64)
        };
        if totp_code_at(&secret, step) == code_num {
            return true;
        }
    }
    false
}

#[derive(Deserialize)]
pub struct OwnerChallengeReq {
    pub game_id: String,
    pub action: String,
}

/// POST /api/v1/sdk/owner/challenge
///
/// Body: `{ "game_id": "...", "action": "rotate_api_key" }`
/// Response: `{ "challenge_id", "canonical_message", "expires_in", "owner_wallet" }`
///
/// Der Client signiert anschließend `canonical_message` mit dem Ed25519-Key
/// des owner_wallet (developer_wallet).
pub async fn handle_owner_challenge(
    State(state): State<AppState>,
    Json(req): Json<OwnerChallengeReq>,
) -> impl IntoResponse {
    if !ALLOWED_OWNER_ACTIONS.contains(&req.action.as_str()) {
        return (StatusCode::BAD_REQUEST,
            err_json(&format!("Unbekannte action '{}'. Erlaubt: {:?}", req.action, ALLOWED_OWNER_ACTIONS)))
            .into_response();
    }

    let store = read_game_store(&state);
    let game = match store.get_game(&req.game_id) {
        Some(g) => g,
        None => return (StatusCode::NOT_FOUND, err_json("Spiel nicht im SDK-Registry")).into_response(),
    };
    let owner_wallet = game.developer_wallet.clone();

    let mut nonce_bytes = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let challenge_id = hex::encode(nonce_bytes);
    let expires_at = now_secs() + OWNER_CHALLENGE_TTL_SECS;

    // Canonical message bindet (action, game_id, nonce, expires_at, owner_wallet)
    // → Signatur kann nicht für andere Aktion oder anderes Spiel wiederverwendet werden.
    let canonical_message = format!(
        "stone-owner-action:{}:{}:{}:{}:{}",
        req.action, req.game_id, owner_wallet, challenge_id, expires_at
    );

    let challenge = OwnerChallenge {
        game_id: req.game_id.clone(),
        action: req.action.clone(),
        owner_wallet: owner_wallet.clone(),
        canonical_message: canonical_message.clone(),
        expires_at,
    };

    {
        let mut map = owner_challenges().lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, c| c.expires_at > now_secs());
        map.insert(challenge_id.clone(), challenge);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "challenge_id": challenge_id,
        "canonical_message": canonical_message,
        "owner_wallet": owner_wallet,
        "action": req.action,
        "game_id": req.game_id,
        "expires_in": OWNER_CHALLENGE_TTL_SECS,
        "hint": "Signiere canonical_message als UTF-8 Bytes mit deinem Ed25519-Wallet-Key und rufe den Action-Endpoint mit { game_id, challenge_id, signature } auf."
    }))).into_response()
}

/// Liest eine Owner-Challenge (ohne sie zu entfernen) und prüft Signatur.
/// Gibt `OwnerChallenge` zurück wenn Signatur gültig — Challenge bleibt im Store.
fn peek_owner_challenge(
    challenge_id: &str,
    expected_game_id: &str,
    expected_action: &str,
    signature_hex: &str,
) -> Result<OwnerChallenge, (StatusCode, String)> {
    let challenge = {
        let map = owner_challenges().lock().unwrap_or_else(|e| e.into_inner());
        map.get(challenge_id)
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "challenge_id unbekannt oder bereits verwendet".to_string()))?
    };
    if challenge.expires_at <= now_secs() {
        // Abgelaufen → aus Store entfernen
        owner_challenges().lock().unwrap_or_else(|e| e.into_inner()).remove(challenge_id);
        return Err((StatusCode::UNAUTHORIZED, "challenge abgelaufen".to_string()));
    }
    if challenge.action != expected_action {
        return Err((StatusCode::UNAUTHORIZED,
            format!("challenge ist für action '{}', nicht '{}'", challenge.action, expected_action)));
    }
    if challenge.game_id != expected_game_id {
        return Err((StatusCode::UNAUTHORIZED,
            format!("challenge ist für game_id '{}', nicht '{}'", challenge.game_id, expected_game_id)));
    }

    // Signatur über canonical_message verifizieren (Ed25519, owner_wallet = pubkey hex)
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let pubkey_bytes = hex::decode(&challenge.owner_wallet)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "owner_wallet kein hex".to_string()))?;
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "owner_wallet kein 32-Byte-Key".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "owner_wallet kein gültiger Ed25519-PubKey".to_string()))?;
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "signature ist kein hex".to_string()))?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "signature ist nicht 64 Bytes".to_string()))?;
    let sig = Signature::from_bytes(&sig_array);
    verifying_key.verify(challenge.canonical_message.as_bytes(), &sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Signatur ungültig".to_string()))?;

    Ok(challenge)
}

/// Entfernt eine Challenge aus dem Store (nach vollständig bestandener Prüfung).
fn finalize_owner_challenge(challenge_id: &str) {
    owner_challenges().lock().unwrap_or_else(|e| e.into_inner()).remove(challenge_id);
}

/// Validiert + konsumiert eine Owner-Challenge.
/// Gibt das `OwnerChallenge`-Objekt zurück wenn:
///   - challenge_id existiert und nicht abgelaufen ist
///   - challenge.action == expected_action
///   - challenge.game_id == expected_game_id
///   - Signatur des canonical_message mit owner_wallet gültig ist
fn consume_owner_challenge(
    challenge_id: &str,
    expected_game_id: &str,
    expected_action: &str,
    signature_hex: &str,
) -> Result<OwnerChallenge, (StatusCode, String)> {
    let challenge = peek_owner_challenge(challenge_id, expected_game_id, expected_action, signature_hex)?;
    finalize_owner_challenge(challenge_id);
    Ok(challenge)
}

#[derive(Deserialize)]
pub struct RotateApiKeyReq {
    pub game_id: String,
    pub challenge_id: String,
    pub signature: String,
    pub totp_code: String,
}

#[derive(Deserialize)]
pub struct OwnerTotpSetupReq {
    pub game_id: String,
    pub challenge_id: String,
    pub signature: String,
}

/// POST /api/v1/sdk/owner/totp/setup
///
/// Body: `{ "game_id", "challenge_id", "signature" }` mit action=`setup_totp`.
/// Response: `{ "totp_secret", "otpauth_url" }`.
///
/// Das Secret wird nur in dieser Antwort ausgegeben.
pub async fn handle_owner_totp_setup(
    State(state): State<AppState>,
    Json(req): Json<OwnerTotpSetupReq>,
) -> impl IntoResponse {
    let challenge = match consume_owner_challenge(
        &req.challenge_id,
        &req.game_id,
        "setup_totp",
        &req.signature,
    ) {
        Ok(c) => c,
        Err((status, msg)) => return (status, err_json(&msg)).into_response(),
    };

    let secret_b32 = generate_totp_secret_b32();
    let set_result = with_game_store_mut(&state, |store| {
        store.set_owner_totp_secret(&req.game_id, &secret_b32)
    });
    if let Err(e) = set_result {
        return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())).into_response();
    }

    let issuer = "Stonechain";
    let label = format!("{}:{}", issuer, req.game_id);
    let otpauth_url = format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        urlencoding::encode(&label),
        secret_b32,
        urlencoding::encode(issuer),
        TOTP_DIGITS,
        TOTP_STEP_SECS,
    );

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "game_id": req.game_id,
        "owner_wallet": challenge.owner_wallet,
        "totp_secret": secret_b32,
        "otpauth_url": otpauth_url,
        "warning": "TOTP-Secret wird nur EINMAL angezeigt. Jetzt in Google Authenticator hinzufügen.",
    }))).into_response()
}

/// POST /api/v1/sdk/owner/api-key/rotate
///
/// Body: `{ "game_id", "challenge_id", "signature" }`
/// Response: `{ "api_key": "sk_...", "warning": "..." }`
///
/// Der neue API-Key wird **nur einmal** zurückgegeben — der alte ist sofort tot.
pub async fn handle_rotate_api_key(
    State(state): State<AppState>,
    Json(req): Json<RotateApiKeyReq>,
) -> impl IntoResponse {
    // Schritt 1: Signatur prüfen (Challenge bleibt im Store)
    let _challenge = match peek_owner_challenge(
        &req.challenge_id, &req.game_id, "rotate_api_key", &req.signature
    ) {
        Ok(c) => c,
        Err((status, msg)) => return (status, err_json(&msg)).into_response(),
    };

    // Schritt 2: TOTP prüfen (Challenge noch im Store → bei Fehler kann der User es nochmal versuchen)
    let totp_secret = {
        let store = read_game_store(&state);
        store.owner_totp_secret(&req.game_id).map(|s| s.to_string())
    };
    let Some(secret_b32) = totp_secret else {
        return (
            StatusCode::PRECONDITION_REQUIRED,
            err_json("TOTP nicht eingerichtet. Bitte zuerst /api/v1/sdk/owner/totp/setup ausführen."),
        ).into_response();
    };
    if !verify_totp_code(&secret_b32, &req.totp_code) {
        return (StatusCode::UNAUTHORIZED, err_json("TOTP-Code ungültig")).into_response();
    }

    // Schritt 3: Alle Checks bestanden → Challenge jetzt endgültig konsumieren (Replay-Schutz)
    finalize_owner_challenge(&req.challenge_id);

    let result = with_game_store_mut(&state, |store| store.rotate_api_key(&req.game_id));
    match result {
        Ok(new_key) => {
            (StatusCode::OK, Json(serde_json::json!({
                "api_key": new_key,
                "game_id": req.game_id,
                "warning": "Dieser API-Key wird nur EINMAL angezeigt. Speichere ihn jetzt sicher. Der alte Key ist ab sofort ungültig.",
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())).into_response(),
    }
}

// ── GET /api/v1/sdk/game/:game_id ───────────────────────────────────────────

/// GET /api/v1/sdk/game/{game_id} – Spiel-Info abrufen (public)
pub async fn handle_sdk_game_info(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    match store.get_game(&game_id) {
        Some(game) => Json(serde_json::json!({
            "ok": true,
            "game": {
                "game_id": game.game_id,
                "name": game.name,
                "description": game.description,
                "website": game.website,
                "permissions": game.permissions,
                "genres": game.genres,
                "max_wallet_limit": game.max_wallet_limit.to_string(),
                "status": game.status,
                "created_at": game.created_at,
            },
        })).into_response(),
        None => (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
    }
}

// ── POST /api/v1/sdk/game/:game_id/status ───────────────────────────────────

#[derive(Deserialize)]
pub struct GameStatusReq {
    pub action: String,   // "suspend", "blacklist", "reactivate"
    pub reason: Option<String>,
    pub until: Option<i64>,
}

/// POST /api/v1/sdk/game/{game_id}/status – Spiel suspendieren/blacklisten (Admin)
pub async fn handle_sdk_game_status(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
    Json(req): Json<GameStatusReq>,
) -> impl IntoResponse {
    let result = with_game_store_mut(&state, |store| {
        match req.action.as_str() {
            "suspend" => store.suspend_game(
                &game_id,
                req.reason.as_deref().unwrap_or("Admin-Entscheidung"),
                req.until,
            ),
            "blacklist" => store.blacklist_game(
                &game_id,
                req.reason.as_deref().unwrap_or("Admin-Entscheidung"),
            ),
            "reactivate" => store.reactivate_game(&game_id),
            _ => Err(stone::token::game_economy::GameEconomyError::InvalidInput {
                reason: "Aktion muss 'suspend', 'blacklist' oder 'reactivate' sein".into(),
            }),
        }
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({
            "game_id": game_id,
            "action": req.action,
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §2 CONSENT – Nutzer-Zustimmung
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/consent/request ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentRequestReq {
    pub player_wallet: String,
    pub requested_limit: String,
    pub requested_permissions: Vec<GamePermission>,
}

/// POST /api/v1/sdk/consent/request – Spiel fordert Nutzer-Consent an (API-Key Auth)
pub async fn handle_sdk_consent_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsentRequestReq>,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let limit: Decimal = match req.requested_limit.parse() {
        Ok(d) if d > Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges Limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.request_consent(&game_id, &req.player_wallet, limit, req.requested_permissions.clone())
    });

    match result {
        Ok(cr) => Json(serde_json::json!({
            "ok": true,
            "consent_request": {
                "request_id": cr.request_id,
                "game_id": cr.game_id,
                "game_name": cr.game_name,
                "player_wallet": cr.player_wallet,
                "requested_limit": cr.requested_limit.to_string(),
                "requested_permissions": cr.requested_permissions,
                "expires_at": cr.expires_at,
            },
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── GET /api/v1/sdk/consent/pending ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentPendingQuery {
    pub wallet: String,
}

/// GET /api/v1/sdk/consent/pending?wallet=... – Offene Consent-Anfragen anzeigen
pub async fn handle_sdk_consent_pending(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ConsentPendingQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let pending = store.pending_consents(&q.wallet);

    let items: Vec<serde_json::Value> = pending.iter().map(|cr| serde_json::json!({
        "request_id": cr.request_id,
        "game_id": cr.game_id,
        "game_name": cr.game_name,
        "requested_limit": cr.requested_limit.to_string(),
        "requested_permissions": cr.requested_permissions,
        "expires_at": cr.expires_at,
    })).collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": items.len(),
        "pending": items,
    }))
}

// ── POST /api/v1/sdk/consent/approve ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentApproveReq {
    pub request_id: String,

    /// **EMPFOHLEN** — Ed25519-Public-Key (Hex oder stone1...) des Spielers.
    /// Zusammen mit `signature` Ownership-Proof ohne Mnemonic-Transfer.
    #[serde(default)]
    pub player_pubkey: Option<String>,

    /// **EMPFOHLEN** — Ed25519-Signatur (Hex) über
    /// `"stone:consent:approve:{request_id}"`.
    #[serde(default)]
    pub signature: Option<String>,

    /// **DEPRECATED** — Mnemonic. Nur aktiv mit `allow_mnemonic_auth: true`
    /// UND wenn der Operator den Killswitch `STONE_DISABLE_MNEMONIC_AUTH` nicht
    /// gesetzt hat.
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub allow_mnemonic_auth: bool,
}

/// POST /api/v1/sdk/consent/approve – Nutzer genehmigt Consent-Anfrage.
///
/// Signatur-Message: `"stone:consent:approve:{request_id}"`.
pub async fn handle_sdk_consent_approve(
    State(state): State<AppState>,
    Json(req): Json<ConsentApproveReq>,
) -> impl IntoResponse {
    let msg = format!("stone:consent:approve:{}", req.request_id).into_bytes();
    let player_addr = match derive_player_address(
        req.player_pubkey.as_deref(),
        req.signature.as_deref(),
        &msg,
        req.mnemonic.as_deref(),
        req.allow_mnemonic_auth,
        "consent_approve",
    ) {
        Ok(a) => a,
        Err((sc, j)) => return (sc, j).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.approve_consent(&player_addr, &req.request_id)
    });

    match result {
        Ok(gw) => Json(serde_json::json!({
            "ok": true,
            "game_wallet": {
                "game_wallet": gw.game_wallet,
                "game_id": gw.game_id,
                "daily_limit": gw.daily_limit.to_string(),
                "allowed_permissions": gw.allowed_permissions,
            },
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/consent/reject ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentRejectReq {
    pub request_id: String,

    #[serde(default)]
    pub player_pubkey: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub allow_mnemonic_auth: bool,
}

/// POST /api/v1/sdk/consent/reject – Nutzer lehnt Consent-Anfrage ab.
///
/// Signatur-Message: `"stone:consent:reject:{request_id}"`.
pub async fn handle_sdk_consent_reject(
    State(state): State<AppState>,
    Json(req): Json<ConsentRejectReq>,
) -> impl IntoResponse {
    let msg = format!("stone:consent:reject:{}", req.request_id).into_bytes();
    let player_addr = match derive_player_address(
        req.player_pubkey.as_deref(),
        req.signature.as_deref(),
        &msg,
        req.mnemonic.as_deref(),
        req.allow_mnemonic_auth,
        "consent_reject",
    ) {
        Ok(a) => a,
        Err((sc, j)) => return (sc, j).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.reject_consent(&player_addr, &req.request_id)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "request_id": req.request_id, "status": "rejected" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §3 WALLET – Spiel-Wallets verwalten
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/wallet/create ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateGameWalletReq {
    pub mnemonic: String,
    pub game_id: String,
    pub display_name: String,
    pub daily_limit: String,
    pub permissions: Vec<GamePermission>,
}

/// POST /api/v1/sdk/wallet/create – Game-Wallet direkt erstellen (Nutzer-Aktion)
pub async fn handle_sdk_wallet_create(
    State(state): State<AppState>,
    Json(req): Json<CreateGameWalletReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_wallet_create")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_wallet_create");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let limit: Decimal = match req.daily_limit.parse() {
        Ok(d) if d > Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges daily_limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.create_game_wallet(
            &wallet.address(), &req.game_id, &req.display_name,
            limit, req.permissions.clone(),
        )
    });

    match result {
        Ok(gw) => Json(serde_json::json!({
            "ok": true,
            "game_wallet": gw,
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/derive ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletDeriveReq {
    pub mnemonic: String,
}

/// POST /api/v1/sdk/wallet/derive – Adresse aus Mnemonic ableiten.
/// Hilfsendpoint für Browser-Clients, die selbst keine BIP39/secp-Crypto haben.
pub async fn handle_sdk_wallet_derive(
    Json(req): Json<WalletDeriveReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_wallet_derive")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_wallet_derive");
    match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => Json(serde_json::json!({ "ok": true, "address": w.address() })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct WalletSignReq {
    pub mnemonic: String,
    /// UTF-8 Klartext-Message, die signiert werden soll (z.B. canonical_message aus Owner-Challenge).
    pub message: String,
}

/// POST /api/v1/sdk/wallet/sign – Beliebige Message mit Ed25519-Schlüssel aus Mnemonic signieren.
/// **Dev/Test only** (mnemonic-killswitch). Echte Clients signieren lokal mit BouncyCastle/TweetNaCl.
pub async fn handle_sdk_wallet_sign(
    Json(req): Json<WalletSignReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_wallet_sign")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_wallet_sign");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };
    use ed25519_dalek::Signer;
    let sig = wallet.signing_key().sign(req.message.as_bytes());
    Json(serde_json::json!({
        "ok": true,
        "address": wallet.address(),
        "signature": hex::encode(sig.to_bytes()),
    })).into_response()
}

#[derive(Deserialize, Default)]
pub struct WalletGenerateReq {
    /// 12 oder 24 (Default: 12, kürzere Test-Wallets)
    #[serde(default)]
    pub words: Option<u16>,
}

/// POST /api/v1/sdk/wallet/generate – Neue Mnemonic + Adresse generieren.
/// **Test/Dev only**: gibt Mnemonic im Klartext zurück. Frontend speichert lokal.
pub async fn handle_sdk_wallet_generate(
    Json(req): Json<WalletGenerateReq>,
) -> impl IntoResponse {
    let words = req.words.unwrap_or(12);
    match Wallet::generate_with_words(words) {
        Ok(w) => Json(serde_json::json!({
            "ok": true,
            "mnemonic": w.mnemonic(),
            "address":  w.address(),
            "words":    words,
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Generate: {e}"))).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/link ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletLinkReq {
    pub game_id: String,
    pub display_name: Option<String>,
    pub daily_limit: Option<String>,
    pub permissions: Option<Vec<GamePermission>>,

    /// **EMPFOHLEN** — Ed25519-Pubkey + Signatur über
    /// `"stone:wallet-link:{game_id}"`.
    #[serde(default)]
    pub player_pubkey: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,

    /// **DEPRECATED** — Mnemonic-Auth nur mit `allow_mnemonic_auth: true`.
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub allow_mnemonic_auth: bool,
}

/// POST /api/v1/sdk/wallet/link – Bestehende Stone-Wallet mit einem Spiel verknüpfen.
///
/// Erzeugt den User-Eintrag (falls nötig) und den Game-Wallet in einem Schritt.
/// Ownership-Proof via Ed25519-Signatur über `"stone:wallet-link:{game_id}"`.
pub async fn handle_sdk_wallet_link(
    State(state): State<AppState>,
    Json(req): Json<WalletLinkReq>,
) -> impl IntoResponse {
    let msg = format!("stone:wallet-link:{}", req.game_id).into_bytes();
    let wallet_addr = match derive_player_address(
        req.player_pubkey.as_deref(),
        req.signature.as_deref(),
        &msg,
        req.mnemonic.as_deref(),
        req.allow_mnemonic_auth,
        "wallet_link",
    ) {
        Ok(a) => a,
        Err((sc, j)) => return (sc, j).into_response(),
    };

    let display_name = req.display_name.unwrap_or_else(|| format!("Wallet-{}", &wallet_addr[..8]));
    let limit: Decimal = req.daily_limit.as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Decimal::new(500, 0));
    let permissions = req.permissions.unwrap_or_else(|| vec![
        GamePermission::Basic, GamePermission::Marketplace, GamePermission::Assets,
    ]);

    // On-chain Balance prüfen
    let main_balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance(&wallet_addr)
    };

    // Game-Wallet erstellen (oder existierenden zurückgeben)
    let gw_result = with_game_store_mut(&state, |store| {
        // Prüfe ob bereits verknüpft
        if let Some(existing) = store.find_game_wallet(&wallet_addr, &req.game_id) {
            return Ok(existing.clone());
        }
        store.create_game_wallet(
            &wallet_addr, &req.game_id, &display_name,
            limit, permissions.clone(),
        )
    });

    match gw_result {
        Ok(gw) => Json(serde_json::json!({
            "ok": true,
            "wallet_address": wallet_addr,
            "main_balance": main_balance.to_string(),
            "game_wallet": gw.game_wallet,
            "game_id": gw.game_id,
            "daily_limit": gw.daily_limit.to_string(),
            "display_name": display_name,
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e.to_string())).into_response(),
    }
}

// ── GET /api/v1/sdk/wallet/balance ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletQuery {
    pub wallet: String,
    pub game_id: Option<String>,
}

/// GET /api/v1/sdk/wallet/balance?wallet=...&game_id=...
pub async fn handle_sdk_wallet_balance(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<WalletQuery>,
) -> impl IntoResponse {
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let main_balance = ledger.balance(&q.wallet);

    let store = read_game_store(&state);

    if let Some(ref gid) = q.game_id {
        if let Some(gw) = store.find_game_wallet(&q.wallet, gid) {
            let game_balance = ledger.balance(&gw.game_wallet);
            return Json(serde_json::json!({
                "ok": true,
                "wallet": q.wallet,
                "main_balance": main_balance.to_string(),
                "game_id": gid,
                "game_wallet": gw.game_wallet,
                "game_balance": game_balance.to_string(),
                "daily_limit": gw.daily_limit.to_string(),
                "spent_today": gw.spent_today.to_string(),
                "frozen": gw.frozen,
            }));
        }
        return Json(serde_json::json!({
            "ok": true,
            "wallet": q.wallet,
            "main_balance": main_balance.to_string(),
            "game_id": gid,
            "game_balance": null,
        }));
    }

    // Alle Game-Wallets mit Balancen
    let game_wallets: Vec<serde_json::Value> = store.wallets_of(&q.wallet)
        .iter()
        .map(|gw| serde_json::json!({
            "game_id": gw.game_id,
            "game_wallet": gw.game_wallet,
            "balance": ledger.balance(&gw.game_wallet).to_string(),
            "daily_limit": gw.daily_limit.to_string(),
            "spent_today": gw.spent_today.to_string(),
            "frozen": gw.frozen,
        }))
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "main_balance": main_balance.to_string(),
        "game_wallets": game_wallets,
    }))
}

// ── GET /api/v1/sdk/wallet/transactions ──────────────────────────────────────

#[derive(Deserialize)]
pub struct TxHistoryQuery {
    pub wallet: String,
    pub limit: Option<usize>,
}

/// GET /api/v1/sdk/wallet/transactions?wallet=...&limit=50
pub async fn handle_sdk_wallet_transactions(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<TxHistoryQuery>,
) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let limit = q.limit.unwrap_or(50).min(200);
    let mut txs: Vec<serde_json::Value> = Vec::new();

    for block in chain.blocks.iter().rev() {
        for tx in &block.transactions {
            if tx.from == q.wallet || tx.to == q.wallet {
                txs.push(serde_json::json!({
                    "tx_id": tx.tx_id,
                    "type": tx.tx_type.to_string(),
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "memo": tx.memo,
                    "timestamp": tx.timestamp,
                    "block_index": block.index,
                }));
                if txs.len() >= limit { break; }
            }
        }
        if txs.len() >= limit { break; }
    }

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": txs.len(),
        "transactions": txs,
    }))
}

// ── POST /api/v1/sdk/wallet/send ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WalletSendReq {
    pub to: String,
    pub amount: String,
    pub memo: Option<String>,
}

/// POST /api/v1/sdk/wallet/send – Coins senden (API-Key Auth, prüft Permission + Limit)
pub async fn handle_sdk_wallet_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<WalletSendReq>,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    // Session-Token aus Header für Wallet-Identifikation
    let session_token = match headers.get("X-SDK-Session").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => return (StatusCode::UNAUTHORIZED, err_json("X-SDK-Session Header fehlt")).into_response(),
    };

    let store = read_game_store(&state);
    let session = match store.validate_session(&session_token) {
        Some(s) => s.clone(),
        None => return (StatusCode::UNAUTHORIZED, err_json("Session ungültig oder abgelaufen")).into_response(),
    };

    if session.game_id != game_id {
        return (StatusCode::FORBIDDEN, err_json("Session gehört nicht zu diesem Spiel")).into_response();
    }

    // Game-Wallet finden
    let game_wallet_addr = derive_game_wallet(&session.wallet, &game_id);

    // Permission-Check
    {
        let store = read_game_store(&state);
        if let Err(e) = store.check_wallet_action(&game_wallet_addr, GamePermission::Basic) {
            return (StatusCode::FORBIDDEN, err_json(&e.to_string())).into_response();
        }
    }

    // Daily-Limit prüfen + registrieren
    {
        let limit_result = with_game_store_mut(&state, |store| {
            store.enforce_daily_limit(&game_wallet_addr, amount)
        });
        if let Err(e) = limit_result {
            return (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response();
        }
    }

    // TX erstellen (System-TX vom Game-Wallet)
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let balance = ledger.balance(&game_wallet_addr);
    if balance < amount {
        return (StatusCode::BAD_REQUEST, err_json(&format!(
            "Nicht genug Guthaben: {} < {}", balance, amount
        ))).into_response();
    }

    let nonce = ledger.nonce(&game_wallet_addr);
    drop(ledger);

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: game_wallet_addr.clone(),
        to: req.to.clone(),
        amount,
        fee: Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: format!("sdk:{}:{}", game_id, session.wallet),
        memo: req.memo.unwrap_or_else(|| format!("SDK-Send: {}", game_id)),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Priority,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            with_game_store_mut(&state, |store| {
                store.audit(&game_id, &session.wallet, "sdk_send", serde_json::json!({
                    "to": req.to, "amount": amount.to_string(),
                }), true);
            });
            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "from": game_wallet_addr,
                "to": req.to,
                "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/withdraw ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct WithdrawReq {
    pub mnemonic: String,
    pub game_id: String,
    pub amount: String,
}

/// POST /api/v1/sdk/wallet/withdraw – Vom Game-Wallet ins Haupt-Wallet
pub async fn handle_sdk_wallet_withdraw(
    State(state): State<AppState>,
    Json(req): Json<WithdrawReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_wallet_withdraw")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_wallet_withdraw");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let store = read_game_store(&state);
    let game_wallet = match store.find_game_wallet(&wallet.address(), &req.game_id) {
        Some(gw) => gw.game_wallet.clone(),
        None => return (StatusCode::NOT_FOUND, err_json("Kein Game-Wallet gefunden")).into_response(),
    };

    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let balance = ledger.balance(&game_wallet);
    if balance < amount {
        return (StatusCode::BAD_REQUEST, err_json(&format!(
            "Nicht genug: {} < {}", balance, amount
        ))).into_response();
    }

    let nonce = ledger.nonce(&game_wallet);
    drop(ledger);

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::Transfer,
        from: game_wallet.clone(),
        to: wallet.address(),
        amount,
        fee: Decimal::ZERO,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: format!("game-withdraw:{}", wallet.address()),
        memo: format!("Withdraw: {} → Main", req.game_id),
        chain_id: default_chain_id(),
        fee_tier: stone::token::FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "from": game_wallet,
                "to": wallet.address(),
                "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── GET /api/v1/sdk/wallet/nft-inventory ─────────────────────────────────────

/// GET /api/v1/sdk/wallet/nft-inventory?wallet=...&game_id=...
///
/// Liefert die NFTs des Wallets. Jedes Item wird um das Feld
/// `usable_in: Vec<game_id>` erweitert: das ursprüngliche Spiel des Items
/// **plus** alle (transitiven) Nachfolger-Spiele, in denen das Item dank
/// `inherited_game_ids` weiter genutzt werden kann.
pub async fn handle_sdk_nft_inventory(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<WalletQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let items: Vec<_> = store.items_of(&q.wallet)
        .into_iter()
        .filter(|i| q.game_id.as_ref().map(|gid| i.game_id == *gid).unwrap_or(true))
        .cloned()
        .collect();

    // Pro Item alle Spiele aufsammeln, in denen es nutzbar ist.
    // Cache je item.game_id, damit wir nicht für jedes Item neu iterieren.
    use std::collections::HashMap;
    let mut usable_cache: HashMap<String, Vec<String>> = HashMap::new();
    let all_game_ids: Vec<String> = store.registered_games.keys().cloned().collect();

    let enriched: Vec<serde_json::Value> = items.iter().map(|i| {
        let usable = usable_cache.entry(i.game_id.clone()).or_insert_with(|| {
            let mut out = vec![i.game_id.clone()];
            for g in &all_game_ids {
                if g == &i.game_id { continue; }
                if store.can_act_on_item(g, &i.game_id) {
                    out.push(g.clone());
                }
            }
            out
        }).clone();
        let mut v = serde_json::to_value(i).unwrap_or(serde_json::json!({}));
        if let Some(obj) = v.as_object_mut() {
            obj.insert("usable_in".into(), serde_json::json!(usable));
        }
        v
    }).collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": enriched.len(),
        "items": enriched,
    }))
}

// ── POST /api/v1/sdk/wallet/freeze ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct FreezeReq {
    pub mnemonic: String,
    pub game_id: String,
}

/// POST /api/v1/sdk/wallet/freeze – Nutzer friert Game-Wallet ein
pub async fn handle_sdk_wallet_freeze(
    State(state): State<AppState>,
    Json(req): Json<FreezeReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_wallet_freeze")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_wallet_freeze");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.freeze_wallet(&wallet.address(), &req.game_id)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "game_id": req.game_id, "status": "frozen" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/unfreeze ─────────────────────────────────────────

/// POST /api/v1/sdk/wallet/unfreeze – Nutzer gibt Game-Wallet frei
pub async fn handle_sdk_wallet_unfreeze(
    State(state): State<AppState>,
    Json(req): Json<FreezeReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.unfreeze_wallet(&wallet.address(), &req.game_id)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "game_id": req.game_id, "status": "active" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/wallet/set-limit ────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetLimitReq {
    pub mnemonic: String,
    pub game_id: String,
    pub daily_limit: String,
}

/// POST /api/v1/sdk/wallet/set-limit – Nutzer passt tägliches Limit an
pub async fn handle_sdk_wallet_set_limit(
    State(state): State<AppState>,
    Json(req): Json<SetLimitReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_wallet_set_limit")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_wallet_set_limit");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let limit: Decimal = match req.daily_limit.parse() {
        Ok(d) if d >= Decimal::ZERO => d,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiges Limit")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.set_daily_limit(&wallet.address(), &req.game_id, limit)
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({
            "game_id": req.game_id,
            "daily_limit": limit.to_string(),
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §4 TX – Transaktionen
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/tx/buy-item ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct MarketBuyExecution {
    pub tx_id: String,
    pub listing_id: String,
    pub total: Decimal,
    pub fee: Decimal,
    pub seller: String,
}

pub(crate) fn execute_market_buy_with_wallet(
    state: &AppState,
    wallet: &Wallet,
    listing_id: &str,
) -> Result<MarketBuyExecution, String> {
    // Oracle-Snapshot vom Testnet-Markt ziehen (Preis "einfrieren" für diesen Kauf).
    let oracle_rate = {
        let m = state.node.testnet_market.read().unwrap_or_else(|e| e.into_inner());
        let p = m.current_price();
        if p.is_finite() && p > 0.0 {
            Decimal::from_f64_retain(p).unwrap_or(Decimal::ONE)
        } else {
            Decimal::ONE
        }
    };
    let oracle = stone::token::FixedOracle(oracle_rate);

    // Preview + Balance prüfen bevor Store mutiert.
    let (preview, item_id_for_anchor) = {
        let store = read_game_store(state);
        let listing = store
            .listings
            .get(listing_id)
            .cloned()
            .ok_or_else(|| "Listing nicht gefunden".to_string())?;

        if !matches!(listing.status, stone::token::game_economy::ListingStatus::Active) {
            return Err("Listing ist nicht aktiv".to_string());
        }
        if listing.seller == wallet.address() {
            return Err("Eigenes Listing kann nicht gekauft werden".to_string());
        }
        if let Some(exp) = listing.expires_at {
            if chrono::Utc::now().timestamp() > exp {
                return Err("Listing ist abgelaufen".to_string());
            }
        }

        let resolved = stone::token::game_economy::resolve_price_stone(
            &listing.price_mode,
            listing.price,
            &oracle,
        )
        .map_err(|e| e.to_string())?;

        (resolved, listing.item_id.clone())
    };

    let preview_fee = (preview.stone
        * Decimal::from(stone::token::game_economy::MARKETPLACE_FEE_PCT)
        / Decimal::from(stone::token::game_economy::MARKETPLACE_FEE_BASE))
    .round_dp(8);
    let preview_total = preview.stone;

    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let bal = ledger.balance(&wallet.address());
        if bal < preview_total {
            return Err(format!(
                "Nicht genug STONE: benötigt {preview_total} (inkl. {preview_fee} Fee), verfügbar {bal}"
            ));
        }
    }

    // Balance OK -> jetzt Store mutieren.
    let buy_result = with_game_store_mut(state, |store| {
        store.buy_item(listing_id, &wallet.address(), &oracle)
    });

    let (fee, seller_amount, seller) = buy_result.map_err(|e| e.to_string())?;
    let total = fee + seller_amount;

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let tx = wallet
        .sign_tx_with_tier(
            TxType::Transfer,
            seller.clone(),
            seller_amount,
            nonce,
            format!("[item:{}] Market-Buy: {}", item_id_for_anchor, listing_id),
            stone::token::FeeTier::Priority,
        )
        .map_err(|e| format!("TX-Sign: {e}"))?;

    let fee_tx = if fee > Decimal::ZERO {
        wallet
            .sign_tx_with_tier(
                TxType::Transfer,
                MARKETPLACE_POOL.to_string(),
                fee,
                nonce + 1,
                format!("Market-Fee: {}", listing_id),
                stone::token::FeeTier::Priority,
            )
            .ok()
    } else {
        None
    };

    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state
            .node
            .mempool
            .add_tx(tx.clone(), Some(&ledger))
            .map_err(|e| format!("Mempool: {e}"))?;
    }
    broadcast_tx(state, tx.clone());

    if let Some(ftx) = fee_tx {
        let _ = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(ftx.clone(), Some(&ledger))
        };
        broadcast_tx(state, ftx);
    }

    // Transfer-History im Item-Metadata anhängen.
    let _ = with_game_store_mut(state, |store| -> Result<(), stone::token::game_economy::GameEconomyError> {
        if let Some(item) = store.items.get_mut(&item_id_for_anchor) {
            let entry = serde_json::json!({
                "tx_id": tx.tx_id.clone(),
                "from": seller.clone(),
                "to": wallet.address(),
                "kind": "sale",
                "ts": chrono::Utc::now().timestamp(),
            });
            let history = item
                .metadata
                .entry("transfer_history".to_string())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(arr) = history.as_array_mut() {
                arr.push(entry);
            }
        }
        Ok(())
    });

    Ok(MarketBuyExecution {
        tx_id: tx.tx_id,
        listing_id: listing_id.to_string(),
        total,
        fee,
        seller,
    })
}

pub(crate) fn execute_market_buy_with_signed_txs(
    state: &AppState,
    listing_id: &str,
    pay_tx: TokenTx,
    fee_tx: Option<TokenTx>,
) -> Result<MarketBuyExecution, String> {
    let buyer_addr = pay_tx.from.clone();

    // Oracle-Snapshot vom Testnet-Markt ziehen (Preis einfrieren).
    let oracle_rate = {
        let m = state.node.testnet_market.read().unwrap_or_else(|e| e.into_inner());
        let p = m.current_price();
        if p.is_finite() && p > 0.0 {
            Decimal::from_f64_retain(p).unwrap_or(Decimal::ONE)
        } else {
            Decimal::ONE
        }
    };
    let oracle = stone::token::FixedOracle(oracle_rate);

    // Preview + Konsistenz prüfen bevor Store mutiert.
    let (preview, item_id_for_anchor, expected_seller) = {
        let store = read_game_store(state);
        let listing = store
            .listings
            .get(listing_id)
            .cloned()
            .ok_or_else(|| "Listing nicht gefunden".to_string())?;

        if !matches!(listing.status, stone::token::game_economy::ListingStatus::Active) {
            return Err("Listing ist nicht aktiv".to_string());
        }
        if listing.seller == buyer_addr {
            return Err("Eigenes Listing kann nicht gekauft werden".to_string());
        }
        if let Some(exp) = listing.expires_at {
            if chrono::Utc::now().timestamp() > exp {
                return Err("Listing ist abgelaufen".to_string());
            }
        }

        let resolved = stone::token::game_economy::resolve_price_stone(
            &listing.price_mode,
            listing.price,
            &oracle,
        )
        .map_err(|e| e.to_string())?;

        (resolved, listing.item_id.clone(), listing.seller)
    };

    let expected_fee = (preview.stone
        * Decimal::from(stone::token::game_economy::MARKETPLACE_FEE_PCT)
        / Decimal::from(stone::token::game_economy::MARKETPLACE_FEE_BASE))
    .round_dp(8);
    let expected_total = preview.stone;
    let expected_seller_amount = expected_total - expected_fee;

    // Signierte Pay-TX validieren (Client-Side-Signing).
    if !matches!(pay_tx.tx_type, TxType::Transfer) {
        return Err("pay_tx muss vom Typ Transfer sein".to_string());
    }
    if pay_tx.from != buyer_addr {
        return Err("pay_tx.from ist inkonsistent".to_string());
    }
    if pay_tx.to != expected_seller {
        return Err("pay_tx.to passt nicht zum Listing-Seller".to_string());
    }
    if pay_tx.amount != expected_seller_amount {
        return Err(format!(
            "pay_tx.amount inkorrekt: erwartet {expected_seller_amount}, erhalten {}",
            pay_tx.amount
        ));
    }
    stone::token::validate_tx(&pay_tx)
        .map_err(|e| format!("pay_tx ungültig: {e}"))?;

    // Fee-TX validieren (wenn Fee > 0 zwingend erforderlich).
    if expected_fee > Decimal::ZERO {
        let ftx = fee_tx
            .clone()
            .ok_or_else(|| "fee_tx fehlt (Marketplace-Fee > 0)".to_string())?;
        if !matches!(ftx.tx_type, TxType::Transfer) {
            return Err("fee_tx muss vom Typ Transfer sein".to_string());
        }
        if ftx.from != buyer_addr {
            return Err("fee_tx.from muss der Käufer sein".to_string());
        }
        if ftx.to != MARKETPLACE_POOL {
            return Err(format!("fee_tx.to muss {MARKETPLACE_POOL} sein"));
        }
        if ftx.amount != expected_fee {
            return Err(format!(
                "fee_tx.amount inkorrekt: erwartet {expected_fee}, erhalten {}",
                ftx.amount
            ));
        }
        stone::token::validate_tx(&ftx)
            .map_err(|e| format!("fee_tx ungültig: {e}"))?;
    } else if fee_tx.is_some() {
        return Err("fee_tx übergeben, obwohl keine Fee fällig ist".to_string());
    }

    // Store mutieren (Item-Transfer).
    let buy_result = with_game_store_mut(state, |store| {
        store.buy_item(listing_id, &buyer_addr, &oracle)
    });
    let (fee, seller_amount, seller) = buy_result.map_err(|e| e.to_string())?;

    // In Mempool einreichen.
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state
            .node
            .mempool
            .add_tx(pay_tx.clone(), Some(&ledger))
            .map_err(|e| format!("Mempool pay_tx: {e}"))?;
    }
    broadcast_tx(state, pay_tx.clone());

    if let Some(ftx) = fee_tx {
        let _ = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(ftx.clone(), Some(&ledger))
        };
        broadcast_tx(state, ftx);
    }

    // Transfer-History anhängen.
    {
        let _ = with_game_store_mut(state, |store| -> Result<(), stone::token::game_economy::GameEconomyError> {
            if let Some(item) = store.items.get_mut(&item_id_for_anchor) {
                let entry = serde_json::json!({
                    "tx_id": pay_tx.tx_id.clone(),
                    "from": seller.clone(),
                    "to": buyer_addr,
                    "kind": "sale",
                    "ts": chrono::Utc::now().timestamp(),
                });
                let history = item
                    .metadata
                    .entry("transfer_history".to_string())
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                if let Some(arr) = history.as_array_mut() {
                    arr.push(entry);
                }
            }
            Ok(())
        });
    }

    Ok(MarketBuyExecution {
        tx_id: pay_tx.tx_id.clone(),
        listing_id: listing_id.to_string(),
        total: fee + seller_amount,
        fee,
        seller,
    })
}

#[derive(Deserialize)]
pub struct BuyItemReq {
    pub mnemonic: String,
    pub listing_id: String,
}

/// POST /api/v1/sdk/tx/buy-item
pub async fn handle_sdk_buy_item(
    State(state): State<AppState>,
    Json(req): Json<BuyItemReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_buy_item")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_buy_item");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    match execute_market_buy_with_wallet(&state, &wallet, &req.listing_id) {
        Ok(exec) => Json(serde_json::json!({
            "ok": true,
            "tx_id": exec.tx_id,
            "listing_id": exec.listing_id,
            "price": exec.total.to_string(),
            "fee": exec.fee.to_string(),
            "seller": exec.seller,
        })).into_response(),
        Err(msg) => (StatusCode::BAD_REQUEST, err_json(&msg)).into_response(),
    }
}

// ── POST /api/v1/sdk/tx/sell-item ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct SellItemReq {
    pub mnemonic: String,
    pub item_id: String,
    pub price: String,
    pub expires_hours: Option<i64>,
    /// Optionale Währung: "stone" (Standard) oder "usd".
    /// Bei "usd" wird der `price`-Wert als USD interpretiert und mit dem
    /// aktuellen Oracle-Kurs in einen STONE-Floor-Preis umgerechnet; der
    /// tatsächliche STONE-Betrag wird beim Kauf erneut zum dann gültigen
    /// Kurs ermittelt.
    #[serde(default)]
    pub currency: Option<String>,
}

/// POST /api/v1/sdk/tx/sell-item
pub async fn handle_sdk_sell_item(
    State(state): State<AppState>,
    Json(req): Json<SellItemReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_sell_item")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_sell_item");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let price: Decimal = match req.price.parse() {
        Ok(p) if p > Decimal::ZERO => p,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Preis")).into_response(),
    };

    let expires_at = req.expires_hours.map(|h| chrono::Utc::now().timestamp() + h * 3600);

    // Oracle-Snapshot aus TestnetMarket (für USD-Mode benötigt).
    let oracle_rate = {
        let m = state.node.testnet_market.read().unwrap_or_else(|e| e.into_inner());
        let p = m.current_price();
        if p.is_finite() && p > 0.0 {
            rust_decimal::Decimal::from_f64_retain(p).unwrap_or(rust_decimal::Decimal::ONE)
        } else {
            rust_decimal::Decimal::ONE
        }
    };
    let oracle = stone::token::FixedOracle(oracle_rate);

    let currency = req.currency.as_deref().unwrap_or("stone").to_lowercase();
    let price_mode = match currency.as_str() {
        "usd" => stone::token::PriceMode::Usd { amount: price },
        "stone" | "" => stone::token::PriceMode::Stone { amount: price },
        other => return (StatusCode::BAD_REQUEST, err_json(&format!("Unbekannte Währung: {other}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.list_item(&wallet.address(), &req.item_id, price_mode, expires_at, &oracle)
    });

    match result {
        Ok(listing) => Json(serde_json::json!({ "ok": true, "listing": listing })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

// ── POST /api/v1/sdk/tx/transfer ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GameTransferReq {
    pub mnemonic: String,
    pub to: String,
    pub amount: String,
    pub memo: Option<String>,
}

/// POST /api/v1/sdk/tx/transfer – Coins an anderen Spieler
pub async fn handle_sdk_transfer(
    State(state): State<AppState>,
    Json(req): Json<GameTransferReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_transfer")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_transfer");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let is_hex64 = req.to.len() == 64 && req.to.chars().all(|c| c.is_ascii_hexdigit());
    let is_game_wallet = req.to.starts_with("game:") && req.to.len() > 5;
    if req.to.is_empty() || (!is_hex64 && !is_game_wallet) {
        return (StatusCode::BAD_REQUEST, err_json("Ungültige Empfänger-Adresse")).into_response();
    }

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer, req.to.clone(), amount, nonce,
        req.memo.unwrap_or_default(),
        stone::token::FeeTier::Priority,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "from": wallet.address(),
                "to": req.to,
                "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── POST /api/v1/sdk/tx/batch ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BatchTxReq {
    pub mnemonic: String,
    pub transactions: Vec<BatchTxEntry>,
}

#[derive(Deserialize)]
pub struct BatchTxEntry {
    pub to: String,
    pub amount: String,
    pub memo: Option<String>,
}

/// POST /api/v1/sdk/tx/batch
pub async fn handle_sdk_batch_tx(
    State(state): State<AppState>,
    Json(req): Json<BatchTxReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_batch_tx")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_batch_tx");
    if req.transactions.is_empty() || req.transactions.len() > MAX_BATCH_SIZE {
        return (StatusCode::BAD_REQUEST, err_json(
            &format!("Batch-Größe muss 1-{MAX_BATCH_SIZE} sein")
        )).into_response();
    }

    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let mut base_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let mut results = Vec::new();
    let mut success_count = 0u32;

    for entry in &req.transactions {
        let amount: Decimal = match entry.amount.parse() {
            Ok(a) if a > Decimal::ZERO => a,
            _ => {
                results.push(serde_json::json!({ "ok": false, "error": "Ungültiger Betrag", "to": entry.to }));
                continue;
            }
        };

        let tx = match wallet.sign_tx_with_tier(
            TxType::Transfer, entry.to.clone(), amount, base_nonce,
            entry.memo.clone().unwrap_or_default(),
            stone::token::FeeTier::Standard,
        ) {
            Ok(t) => t,
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "error": e.to_string(), "to": entry.to }));
                continue;
            }
        };

        let add_result = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(tx.clone(), Some(&ledger))
        };

        match add_result {
            Ok(_) => {
                broadcast_tx(&state, tx.clone());
                results.push(serde_json::json!({
                    "ok": true, "tx_id": tx.tx_id, "to": entry.to, "amount": amount.to_string(),
                }));
                base_nonce += 1;
                success_count += 1;
            }
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "error": e.to_string(), "to": entry.to }));
            }
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "total": req.transactions.len(),
        "success": success_count,
        "results": results,
    })).into_response()
}

// ── GET /api/v1/sdk/tx/status/:tx_id ────────────────────────────────────────

/// GET /api/v1/sdk/tx/status/{tx_id}
pub async fn handle_sdk_tx_status(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> impl IntoResponse {
    let pending = state.node.mempool.pending_txs();
    if let Some(tx) = pending.iter().find(|t| t.tx_id == tx_id) {
        return Json(serde_json::json!({
            "ok": true, "tx_id": tx_id, "status": "pending",
            "tx": { "from": tx.from, "to": tx.to, "amount": tx.amount.to_string(), "timestamp": tx.timestamp },
        }));
    }

    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    for block in chain.blocks.iter().rev() {
        if let Some(tx) = block.transactions.iter().find(|t| t.tx_id == tx_id) {
            return Json(serde_json::json!({
                "ok": true, "tx_id": tx_id, "status": "confirmed",
                "block_index": block.index, "block_hash": block.hash,
                "tx": { "from": tx.from, "to": tx.to, "amount": tx.amount.to_string(), "timestamp": tx.timestamp },
            }));
        }
    }

    Json(serde_json::json!({ "ok": false, "tx_id": tx_id, "status": "not_found" }))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §5 MARKETPLACE
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct ListingsQuery {
    pub category: Option<String>,
    pub game_id: Option<String>,
}

/// GET /api/v1/sdk/market/listings?category=weapon&game_id=...
pub async fn handle_sdk_market_listings(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ListingsQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let mut listings = store.active_listings(q.category.as_deref());
    if let Some(ref gid) = q.game_id {
        listings.retain(|l| l.item.game_id == *gid);
    }
    Json(serde_json::json!({ "ok": true, "count": listings.len(), "listings": listings }))
}

/// POST /api/v1/sdk/market/list (alias für sell-item)
pub async fn handle_sdk_market_list(
    state: State<AppState>,
    json: Json<SellItemReq>,
) -> impl IntoResponse {
    handle_sdk_sell_item(state, json).await
}

#[derive(Deserialize)]
pub struct MarketBuyReq {
    pub listing_id: String,

    /// Signierte Payment-TX (Client-Side-Signing).
    #[serde(default)]
    pub pay_tx: Option<TokenTx>,

    /// Optionale signierte Fee-TX an MARKETPLACE_POOL.
    #[serde(default)]
    pub fee_tx: Option<TokenTx>,

    /// Legacy-Pfad (deprecated): serverseitiges Signieren.
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub allow_mnemonic_auth: bool,
}

/// POST /api/v1/sdk/market/buy
///
/// Bevorzugt signierte TXs (`pay_tx` + optional `fee_tx`) statt Mnemonic.
pub async fn handle_sdk_market_buy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MarketBuyReq>,
) -> impl IntoResponse {
    // SDK-Auth erzwingen
    if let Err((sc, j)) = validate_sdk_key(&state, &headers) {
        return (sc, j).into_response();
    }

    let listing_id = req.listing_id.trim();
    if listing_id.is_empty() {
        return (StatusCode::BAD_REQUEST, err_json("listing_id fehlt")).into_response();
    }

    if let Some(pay_tx) = req.pay_tx {
        let exec = match execute_market_buy_with_signed_txs(&state, listing_id, pay_tx, req.fee_tx) {
            Ok(v) => v,
            Err(msg) => return (StatusCode::BAD_REQUEST, err_json(&msg)).into_response(),
        };

        return Json(serde_json::json!({
            "ok": true,
            "mode": "signed_tx",
            "tx_id": exec.tx_id,
            "listing_id": exec.listing_id,
            "price": exec.total.to_string(),
            "fee": exec.fee.to_string(),
            "seller": exec.seller,
        })).into_response();
    }

    // Legacy: Mnemonic-basiert (nur explizit erlaubt)
    let mnemonic = match req.mnemonic {
        Some(m) if !m.trim().is_empty() => m,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                err_json("Sende pay_tx (+ optional fee_tx) oder legacy mnemonic"),
            )
                .into_response();
        }
    };

    if !req.allow_mnemonic_auth {
        return (
            StatusCode::BAD_REQUEST,
            err_json(
                "Mnemonic-basierter Kauf ist deprecated. Bitte signierte TXs senden. Für Legacy-Tests: allow_mnemonic_auth=true.",
            ),
        )
            .into_response();
    }

    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (
            axum::http::StatusCode::GONE,
            axum::Json(crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_market_buy")),
        )
            .into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_market_buy");

    let wallet = match Wallet::from_mnemonic(mnemonic.trim()) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    match execute_market_buy_with_wallet(&state, &wallet, listing_id) {
        Ok(exec) => Json(serde_json::json!({
            "ok": true,
            "mode": "legacy_mnemonic",
            "tx_id": exec.tx_id,
            "listing_id": exec.listing_id,
            "price": exec.total.to_string(),
            "fee": exec.fee.to_string(),
            "seller": exec.seller,
        })).into_response(),
        Err(msg) => (StatusCode::BAD_REQUEST, err_json(&msg)).into_response(),
    }
}

#[derive(Deserialize)]
pub struct DelistReq {
    pub mnemonic: String,
    pub listing_id: String,
}

/// POST /api/v1/sdk/market/delist
pub async fn handle_sdk_market_delist(
    State(state): State<AppState>,
    Json(req): Json<DelistReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_market_delist")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_market_delist");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.delist_item(&req.listing_id, &wallet.address())
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "listing_id": req.listing_id, "status": "cancelled" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct OfferReq {
    pub mnemonic: String,
    pub listing_id: String,
    pub amount: String,
}

/// POST /api/v1/sdk/market/offer
pub async fn handle_sdk_market_offer(
    State(state): State<AppState>,
    Json(req): Json<OfferReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_market_offer")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_market_offer");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.place_offer(&req.listing_id, &wallet.address(), amount)
    });

    match result {
        Ok(offer) => Json(serde_json::json!({ "ok": true, "offer": offer })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

/// GET /api/v1/sdk/market/history/{item_id}
pub async fn handle_sdk_market_history(
    State(state): State<AppState>,
    Path(item_id): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let history = store.price_history.get(&item_id).cloned().unwrap_or_default();
    Json(serde_json::json!({ "ok": true, "item_id": item_id, "count": history.len(), "history": history }))
}

/// GET /api/v1/sdk/market/floor/{category}
pub async fn handle_sdk_market_floor(
    State(state): State<AppState>,
    Path(category): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    match store.floor_price(&category) {
        Some((price, listing_id)) => Json(serde_json::json!({
            "ok": true, "category": category, "floor_price": price.to_string(), "listing_id": listing_id,
        })),
        None => Json(serde_json::json!({
            "ok": true, "category": category, "floor_price": null, "listing_id": null,
        })),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §6 GAME – Rewards, Burn, Leaderboard, Tournament
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct GameRewardReq {
    pub game_id: String,
    pub server_wallet_mnemonic: String,
    pub player_wallet: String,
    pub amount: String,
    pub reason: Option<String>,
}

/// POST /api/v1/sdk/game/reward – Belohnung ausschütten (Game-Server Auth)
pub async fn handle_sdk_game_reward(
    State(state): State<AppState>,
    Json(req): Json<GameRewardReq>,
) -> impl IntoResponse {
    let server_wallet = match Wallet::from_mnemonic(&req.server_wallet_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Server-Mnemonic: {e}"))).into_response(),
    };

    {
        let store = read_game_store(&state);
        if !store.is_game_server_or_successor(&req.game_id, &server_wallet.address()) {
            return (StatusCode::FORBIDDEN, err_json(
                "Nicht der registrierte Game-Server (auch kein Nachfolger-Server)"
            )).into_response();
        }
        if !store.game_has_permission(&req.game_id, GamePermission::Tournament) {
            return (StatusCode::FORBIDDEN, err_json("Spiel hat keine 'tournament' Berechtigung")).into_response();
        }
    }

    let amount: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&server_wallet.address()) + state.node.mempool.sender_pending_count(&server_wallet.address())
    };

    let memo = req.reason.unwrap_or_else(|| format!("Game-Reward: {}", req.game_id));
    let tx = match server_wallet.sign_tx_with_tier(
        TxType::Transfer, req.player_wallet.clone(), amount, nonce, memo,
        stone::token::FeeTier::Standard,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());
            with_game_store_mut(&state, |store| {
                store.audit(&req.game_id, &req.player_wallet, "game_reward", serde_json::json!({
                    "amount": amount.to_string(),
                }), true);
                store.touch_owner_heartbeat(&req.game_id, &server_wallet.address());
            });
            Json(serde_json::json!({
                "ok": true, "tx_id": tx.tx_id, "player": req.player_wallet, "amount": amount.to_string(),
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct BurnItemReq {
    pub mnemonic: String,
    pub item_id: String,
}

// ── POST /api/v1/sdk/game/server/add ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddServerKeyReq {
    /// Mnemonic des Owners (developer_wallet des Spiels). Wird nur zur lokalen
    /// Owner-Authentifizierung verwendet, nicht persistiert.
    pub owner_mnemonic: String,
    pub game_id: String,
    /// Hex-Pubkey (64 Zeichen) ODER `stone1...` Bech32m-Adresse des neuen Server-Wallets.
    pub server_pubkey: String,
    #[serde(default)]
    pub label: Option<String>,
    /// Optionaler Sub-Scope. Leer/None = Server erbt alle Spiel-Permissions.
    #[serde(default)]
    pub permissions: Option<Vec<GamePermission>>,
}

/// POST /api/v1/sdk/game/server/add – Owner autorisiert einen weiteren Server-Key.
pub async fn handle_sdk_game_server_add(
    State(state): State<AppState>,
    Json(req): Json<AddServerKeyReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_game_server_add")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_game_server_add");
    let owner = match Wallet::from_mnemonic(&req.owner_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Owner-Mnemonic: {e}"))).into_response(),
    };
    // Pubkey normalisieren (akzeptiere stone1... oder Hex).
    let server_hex = match stone::token::address::normalize_to_hex(&req.server_pubkey) {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST,
            err_json("Server-Pubkey: weder 64-Hex noch stone1...-Adresse")).into_response(),
    };
    let label = req.label.unwrap_or_else(|| "unnamed".to_string());
    let perms = req.permissions.unwrap_or_default();

    let result = with_game_store_mut(&state, |store| {
        let r = store.add_server_key(&req.game_id, &owner.address(), &server_hex, &label, perms);
        if r.is_ok() {
            store.touch_owner_heartbeat(&req.game_id, &owner.address());
        }
        r
    });
    match result {
        Ok(entry) => Json(serde_json::json!({ "ok": true, "server": entry })).into_response(),
        Err(e) => {
            let code = match &e {
                stone::token::game_economy::GameEconomyError::Unauthorized { .. } => StatusCode::FORBIDDEN,
                stone::token::game_economy::GameEconomyError::NotFound { .. }    => StatusCode::NOT_FOUND,
                stone::token::game_economy::GameEconomyError::AlreadyExists { .. } => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            (code, err_json(&e.to_string())).into_response()
        }
    }
}

// ── POST /api/v1/sdk/game/server/revoke ──────────────────────────────────────

#[derive(Deserialize)]
pub struct RevokeServerKeyReq {
    pub owner_mnemonic: String,
    pub game_id: String,
    pub server_pubkey: String,
}

/// POST /api/v1/sdk/game/server/revoke – Owner widerruft einen Server-Key.
pub async fn handle_sdk_game_server_revoke(
    State(state): State<AppState>,
    Json(req): Json<RevokeServerKeyReq>,
) -> impl IntoResponse {
    let owner = match Wallet::from_mnemonic(&req.owner_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Owner-Mnemonic: {e}"))).into_response(),
    };
    let server_hex = match stone::token::address::normalize_to_hex(&req.server_pubkey) {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST,
            err_json("Server-Pubkey: weder 64-Hex noch stone1...-Adresse")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        let r = store.revoke_server_key(&req.game_id, &owner.address(), &server_hex);
        if r.is_ok() {
            store.touch_owner_heartbeat(&req.game_id, &owner.address());
        }
        r
    });
    match result {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => {
            let code = match &e {
                stone::token::game_economy::GameEconomyError::Unauthorized { .. } => StatusCode::FORBIDDEN,
                stone::token::game_economy::GameEconomyError::NotFound { .. }    => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_REQUEST,
            };
            (code, err_json(&e.to_string())).into_response()
        }
    }
}

// ── GET /api/v1/sdk/game/:game_id/servers ────────────────────────────────────

/// GET /api/v1/sdk/game/{game_id}/servers – Liste autorisierter Server-Keys (public).
/// Enthält Owner + alle (auch revozierte) Server-Keys mit Status.
pub async fn handle_sdk_game_servers_list(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let game = match store.get_game(&game_id) {
        Some(g) => g,
        None => return (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
    };
    Json(serde_json::json!({
        "ok": true,
        "owner": game.developer_wallet,
        "servers": store.list_server_keys(&game_id),
    })).into_response()
}

// ── POST /api/v1/sdk/game/drop ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GameDropReq {
    pub game_id: String,
    pub server_wallet_mnemonic: String,
    pub player_wallet: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    /// "common" | "uncommon" | "rare" | "epic" | "legendary"
    #[serde(default)]
    pub rarity: Option<String>,
    /// Optional: feste item_id. Sonst auto-generiert.
    #[serde(default)]
    pub item_id: Option<String>,
    #[serde(default)]
    pub transferable: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Optionale Stats/Effekte (damage, armor, crit_bonus, effect, …). Wird in
    /// `item.metadata` zusammengeführt – Schlüssel-Kollisionen mit Server-
    /// gesetzten Feldern (`anchor_tx_id`, `reason`) werden verworfen.
    #[serde(default)]
    pub metadata: Option<std::collections::HashMap<String, serde_json::Value>>,
}

/// POST /api/v1/sdk/game/drop – Loot-Drop: Server-Wallet mintet ein NFT direkt
/// in das Inventar eines Spielers. **Keine STONE-Bezahlung durch den Spieler.**
/// Erfordert `Assets`-Permission und das registrierte Server-Wallet.
pub async fn handle_sdk_game_drop(
    State(state): State<AppState>,
    Json(req): Json<GameDropReq>,
) -> impl IntoResponse {
    let server_wallet = match Wallet::from_mnemonic(&req.server_wallet_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Server-Mnemonic: {e}"))).into_response(),
    };

    {
        let store = read_game_store(&state);
        let game = match store.get_game(&req.game_id) {
            Some(g) => g,
            None => return (StatusCode::NOT_FOUND,
                err_json(&format!("Spiel '{}' ist nicht registriert", req.game_id))).into_response(),
        };
        let signer = server_wallet.address();
        if !store.is_game_server_or_successor(&req.game_id, &signer) {
            // Detaillierte Fehlermeldung: zeige Owner-Adresse und Hinweis auf Server-Keys.
            let active = game.authorized_servers.iter().filter(|s| s.revoked_at.is_none()).count();
            return (StatusCode::FORBIDDEN, err_json(&format!(
                "Wallet {signer} ist nicht autorisiert für Spiel '{}' (auch nicht über Nachfolger-Kette). \
                 Owner: {}. Zusätzlich autorisierte Server-Keys: {}. \
                 Lösung: dieses Wallet als Server-Key registrieren (POST /sdk/game/server/add) \
                 oder mit dem Owner-Wallet signieren.",
                req.game_id, game.developer_wallet, active
            ))).into_response();
        }
        if !store.server_can(&req.game_id, &signer, GamePermission::Assets) {
            return (StatusCode::FORBIDDEN, err_json(
                "Dieser Server-Key hat keine 'assets'-Permission für dieses Spiel"
            )).into_response();
        }
    }

    let rarity = match req.rarity.as_deref() {
        Some("uncommon")  => stone::token::game_economy::ItemRarity::Uncommon,
        Some("rare")      => stone::token::game_economy::ItemRarity::Rare,
        Some("epic")      => stone::token::game_economy::ItemRarity::Epic,
        Some("legendary") => stone::token::game_economy::ItemRarity::Legendary,
        Some("common") | None => stone::token::game_economy::ItemRarity::Common,
        Some(other) => {
            return (StatusCode::BAD_REQUEST, err_json(&format!("Unbekannte Rarität: {other}"))).into_response();
        }
    };

    let item_id = req.item_id.unwrap_or_else(|| {
        format!("drop-{}-{}", req.game_id, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0))
    });
    let description = req.description.unwrap_or_else(|| format!("Loot von {}", req.game_id));
    let category    = req.category.unwrap_or_else(|| "loot".to_string());
    let transferable = req.transferable.unwrap_or(true);
    let creator = server_wallet.address();
    let rarity_str = rarity.to_string();

    // ── 1) On-Chain Anchor: minimal-amount Transfer TX server_wallet → player_wallet.
    //    Erst wenn diese TX im Mempool akzeptiert ist, minten wir das Item.
    //    Damit überlebt jeder Loot-Drop auch einen Node-DB-Verlust – die
    //    Mint-Events sind via Konsens auf der Chain.
    //    Server-Wallet braucht mind. 0.0001 STONE (Standard-Fee) + 0.00000001 (anchor amount).
    //    `Transfer` verlangt amount > 0; wir nutzen 1 Stone-Satoshi (1e-8) als
    //    symbolischen Betrag, der dem Spieler bei jedem Drop zufließt.
    let anchor_amount = Decimal::new(1, 8); // 0.00000001 STONE
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let bal = ledger.balance(&server_wallet.address());
        let fee = stone::token::FeeTier::Standard.fee();
        let needed = fee + anchor_amount;
        if bal < needed {
            return (StatusCode::BAD_REQUEST, err_json(&format!(
                "Server-Wallet hat zu wenig STONE für On-Chain Anchor (benötigt {needed}, verfügbar {bal})"
            ))).into_response();
        }
    }

    let anchor_memo = format!(
        "game-mint:{{\"game_id\":\"{}\",\"item_id\":\"{}\",\"rarity\":\"{}\",\"name\":\"{}\"}}",
        req.game_id, item_id, rarity_str,
        req.name.replace('"', "'")
    );

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&server_wallet.address())
            + state.node.mempool.sender_pending_count(&server_wallet.address())
    };

    let anchor_tx = match server_wallet.sign_tx_with_tier(
        TxType::Transfer,
        req.player_wallet.clone(),
        anchor_amount,
        nonce,
        anchor_memo,
        stone::token::FeeTier::Standard,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let mempool_result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(anchor_tx.clone(), Some(&ledger))
    };
    if let Err(e) = mempool_result {
        return (StatusCode::BAD_REQUEST, err_json(&format!("On-Chain Anchor abgelehnt: {e}"))).into_response();
    }
    broadcast_tx(&state, anchor_tx.clone());

    // ── 2) Mint im Game-Store. tx_id landet in item.metadata für Audit.
    let mut metadata = std::collections::HashMap::new();
    // Erst Client-Metadata (Stats, Effekte) übernehmen…
    if let Some(client_meta) = req.metadata {
        for (k, v) in client_meta {
            // Reserved Keys nicht überschreiben.
            if k == "anchor_tx_id" || k == "reason" { continue; }
            metadata.insert(k, v);
        }
    }
    // …dann Server-Felder setzen (haben Vorrang).
    metadata.insert("anchor_tx_id".to_string(), serde_json::json!(anchor_tx.tx_id));
    if let Some(ref reason) = req.reason {
        metadata.insert("reason".to_string(), serde_json::json!(reason));
    }

    let result = with_game_store_mut(&state, |store| {
        store.mint_item(
            &item_id, &req.name, &description, &category,
            rarity, &req.player_wallet, &req.game_id, &creator,
            metadata,
            transferable,
        ).map(|item| {
            store.audit(&req.game_id, &req.player_wallet, "game_drop", serde_json::json!({
                "item_id":      item.item_id,
                "rarity":       item.rarity.to_string(),
                "reason":       req.reason,
                "anchor_tx_id": anchor_tx.tx_id,
            }), true);
            store.touch_owner_heartbeat(&req.game_id, &creator);
            item
        })
    });

    match result {
        Ok(item) => Json(serde_json::json!({
            "ok":           true,
            "item":         item,
            "anchor_tx_id": anchor_tx.tx_id,
        })).into_response(),
        Err(e)   => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

/// POST /api/v1/sdk/game/burn – Item verbrennen
pub async fn handle_sdk_game_burn(
    State(state): State<AppState>,
    Json(req): Json<BurnItemReq>,
) -> impl IntoResponse {
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        store.burn_item(&req.item_id, &wallet.address())
    });

    match result {
        Ok(_) => ok_json(serde_json::json!({ "item_id": req.item_id, "status": "burned" })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LeaderboardQuery {
    pub game_id: String,
    pub limit: Option<usize>,
}

/// GET /api/v1/sdk/game/leaderboard?game_id=...&limit=100
pub async fn handle_sdk_game_leaderboard(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<LeaderboardQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let board = store.leaderboard(&q.game_id, q.limit.unwrap_or(100).min(500));
    Json(serde_json::json!({ "ok": true, "game_id": q.game_id, "count": board.len(), "leaderboard": board }))
}

#[derive(Deserialize)]
pub struct TournamentPrizeReq {
    pub game_id: String,
    pub server_wallet_mnemonic: String,
    pub prizes: Vec<PrizeEntry>,
}

#[derive(Deserialize)]
pub struct PrizeEntry {
    pub wallet: String,
    pub amount: String,
    pub rank: u32,
}

/// POST /api/v1/sdk/game/tournament/prize – Turnierpreise
pub async fn handle_sdk_tournament_prize(
    State(state): State<AppState>,
    Json(req): Json<TournamentPrizeReq>,
) -> impl IntoResponse {
    let server_wallet = match Wallet::from_mnemonic(&req.server_wallet_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Server-Mnemonic: {e}"))).into_response(),
    };

    {
        let store = read_game_store(&state);
        if !store.is_game_server_or_successor(&req.game_id, &server_wallet.address()) {
            return (StatusCode::FORBIDDEN, err_json(
                "Nicht der registrierte Game-Server (auch kein Nachfolger-Server)"
            )).into_response();
        }
        if !store.game_has_permission(&req.game_id, GamePermission::Tournament) {
            return (StatusCode::FORBIDDEN, err_json("Keine 'tournament' Berechtigung")).into_response();
        }
    }

    if req.prizes.is_empty() || req.prizes.len() > 50 {
        return (StatusCode::BAD_REQUEST, err_json("1-50 Preise erlaubt")).into_response();
    }

    let mut base_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&server_wallet.address()) + state.node.mempool.sender_pending_count(&server_wallet.address())
    };

    let mut results = Vec::new();
    for prize in &req.prizes {
        let amount: Decimal = match prize.amount.parse() {
            Ok(a) if a > Decimal::ZERO => a,
            _ => {
                results.push(serde_json::json!({ "ok": false, "wallet": prize.wallet, "error": "Ungültiger Betrag" }));
                continue;
            }
        };

        let tx = match server_wallet.sign_tx_with_tier(
            TxType::Transfer, prize.wallet.clone(), amount, base_nonce,
            format!("Tournament #{} Rank #{}", req.game_id, prize.rank),
            stone::token::FeeTier::Standard,
        ) {
            Ok(t) => t,
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "wallet": prize.wallet, "error": e.to_string() }));
                continue;
            }
        };

        let add_result = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(tx.clone(), Some(&ledger))
        };

        match add_result {
            Ok(_) => {
                broadcast_tx(&state, tx.clone());
                results.push(serde_json::json!({
                    "ok": true, "tx_id": tx.tx_id, "wallet": prize.wallet,
                    "amount": amount.to_string(), "rank": prize.rank,
                }));
                base_nonce += 1;
            }
            Err(e) => {
                results.push(serde_json::json!({ "ok": false, "wallet": prize.wallet, "error": e.to_string() }));
            }
        }
    }

    // Owner-Aktivität → Heartbeat (server_wallet ist hier authorized_server).
    with_game_store_mut(&state, |store| {
        store.touch_owner_heartbeat(&req.game_id, &server_wallet.address());
    });

    Json(serde_json::json!({
        "ok": true, "game_id": req.game_id,
        "prizes_distributed": results.iter().filter(|r| r["ok"] == true).count(),
        "results": results,
    })).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §7 AUTH – Sessions & Permissions
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct LinkWalletReq {
    pub player_id: String,
    pub game_id: String,

    /// **EMPFOHLEN** — Ed25519-Pubkey + Signatur über
    /// `"stone:link-wallet:{player_id}:{game_id}"`
    #[serde(default)]
    pub player_pubkey: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,

    /// **DEPRECATED** — Mnemonic-Auth nur mit `allow_mnemonic_auth: true`.
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub allow_mnemonic_auth: bool,
}

/// POST /api/v1/sdk/auth/link-wallet
///
/// Verknüpft eine bestehende Player-ID mit einer Wallet. Ownership-Proof
/// via Ed25519-Signatur über `"stone:link-wallet:{player_id}:{game_id}"`.
pub async fn handle_sdk_link_wallet(
    State(state): State<AppState>,
    Json(req): Json<LinkWalletReq>,
) -> impl IntoResponse {
    let msg = format!("stone:link-wallet:{}:{}", req.player_id, req.game_id).into_bytes();
    let player_addr = match derive_player_address(
        req.player_pubkey.as_deref(),
        req.signature.as_deref(),
        &msg,
        req.mnemonic.as_deref(),
        req.allow_mnemonic_auth,
        "link_wallet",
    ) {
        Ok(a) => a,
        Err((sc, j)) => return (sc, j).into_response(),
    };

    let link = with_game_store_mut(&state, |store| {
        store.link_wallet(&req.player_id, &req.game_id, &player_addr)
    });

    Json(serde_json::json!({ "ok": true, "link": link })).into_response()
}

#[derive(Deserialize)]
pub struct CreateSessionReq {
    pub mnemonic: String,
    pub game_id: String,
    pub permissions: Option<Vec<GamePermission>>,
}

/// POST /api/v1/sdk/auth/session – SDK-Session starten
pub async fn handle_sdk_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_session")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_session");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };

    let permissions = req.permissions.unwrap_or_else(|| vec![GamePermission::Basic]);

    let session = with_game_store_mut(&state, |store| {
        store.create_session(&wallet.address(), &req.game_id, permissions)
    });

    Json(serde_json::json!({
        "ok": true,
        "session": {
            "token": session.token,
            "wallet": session.wallet,
            "game_id": session.game_id,
            "permissions": session.permissions,
            "expires_at": session.expires_at,
        },
    })).into_response()
}

#[derive(Deserialize)]
pub struct RevokeSessionReq {
    pub token: String,
}

/// POST /api/v1/sdk/auth/revoke
pub async fn handle_sdk_revoke(
    State(state): State<AppState>,
    Json(req): Json<RevokeSessionReq>,
) -> impl IntoResponse {
    let result = with_game_store_mut(&state, |store| store.revoke_session(&req.token));
    match result {
        Ok(_) => ok_json(serde_json::json!({ "status": "revoked" })).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, err_json(&e.to_string())).into_response(),
    }
}

#[derive(Deserialize)]
pub struct PermissionsQuery {
    pub token: String,
}

/// GET /api/v1/sdk/auth/permissions?token=...
pub async fn handle_sdk_permissions(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<PermissionsQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    match store.validate_session(&q.token) {
        Some(session) => Json(serde_json::json!({
            "ok": true,
            "wallet": session.wallet,
            "game_id": session.game_id,
            "permissions": session.permissions,
            "expires_at": session.expires_at,
        })),
        None => Json(serde_json::json!({ "ok": false, "error": "Session ungültig oder abgelaufen" })),
    }
}

// ── GET /api/v1/sdk/auth/audit-log ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub wallet: Option<String>,
    pub game_id: Option<String>,
    pub limit: Option<usize>,
}

/// GET /api/v1/sdk/auth/audit-log?wallet=...&game_id=...&limit=100
pub async fn handle_sdk_audit_log(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AuditLogQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let limit = q.limit.unwrap_or(100).min(1000);

    let entries: Vec<&stone::token::game_economy::AuditLogEntry> = if let Some(ref wallet) = q.wallet {
        store.audit_log_for_player(wallet, limit)
    } else if let Some(ref gid) = q.game_id {
        store.audit_log_for_game(gid, limit)
    } else {
        store.audit_log.iter().rev().take(limit).collect()
    };

    Json(serde_json::json!({
        "ok": true,
        "count": entries.len(),
        "audit_log": entries,
    }))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §8 PLAYER DASHBOARD – Übersicht für den Nutzer
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct PlayerQuery {
    pub wallet: String,
}

/// GET /api/v1/sdk/player/wallets?wallet=... – Alle Game-Wallets des Nutzers
pub async fn handle_sdk_player_wallets(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<PlayerQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());

    let wallets: Vec<serde_json::Value> = store.wallets_of(&q.wallet)
        .iter()
        .map(|gw| {
            let game_name = store.get_game(&gw.game_id)
                .map(|g| g.name.as_str())
                .unwrap_or("Unbekannt");
            serde_json::json!({
                "game_id": gw.game_id,
                "game_name": game_name,
                "game_wallet": gw.game_wallet,
                "balance": ledger.balance(&gw.game_wallet).to_string(),
                "daily_limit": gw.daily_limit.to_string(),
                "spent_today": gw.spent_today.to_string(),
                "frozen": gw.frozen,
                "permissions": gw.allowed_permissions,
                "created_at": gw.created_at,
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "main_balance": ledger.balance(&q.wallet).to_string(),
        "game_wallets_count": wallets.len(),
        "game_wallets": wallets,
    }))
}

/// GET /api/v1/sdk/player/activity?wallet=...&limit=50 – Letzte Aktivitäten
pub async fn handle_sdk_player_activity(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<TxHistoryQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let limit = q.limit.unwrap_or(50).min(200);
    let audit = store.audit_log_for_player(&q.wallet, limit);

    Json(serde_json::json!({
        "ok": true,
        "wallet": q.wallet,
        "count": audit.len(),
        "activity": audit,
    }))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §9 DEVELOPER DASHBOARD – Übersicht für Spielentwickler
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/sdk/developer/dashboard – Dashboard für den Entwickler (X-SDK-Key nötig)
///
/// Gibt alle relevanten Infos zurück: Spiel-Details, Guthaben,
/// aktive Spieler-Wallets, Items, offene Listings, letzte Audit-Einträge.
pub async fn handle_sdk_developer_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let store = read_game_store(&state);

    let game = match store.registered_games.get(&game_id) {
        Some(g) => g.clone(),
        None => return (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
    };

    // Entwickler-Wallet Balance
    let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let dev_balance = ledger.balance(&game.developer_wallet);

    // Treasury-Wallet (Einnahmen aus dem Shop)
    let treasury_addr = derive_game_wallet(&game.developer_wallet, &game_id);
    let treasury_balance = ledger.balance(&treasury_addr);
    drop(ledger);

    // Alle Spieler-Wallets dieses Spiels
    let player_wallets: Vec<serde_json::Value> = store.game_wallets.values()
        .filter(|gw| gw.game_id == game_id)
        .map(|gw| {
            let bal = state.node.token_ledger.read()
                .unwrap_or_else(|e| e.into_inner())
                .balance(&gw.game_wallet);
            serde_json::json!({
                "owner": gw.owner_wallet,
                "game_wallet": gw.game_wallet,
                "balance": bal.to_string(),
                "daily_limit": gw.daily_limit.to_string(),
                "frozen": gw.frozen,
            })
        })
        .collect();

    // Items dieses Spiels
    let items: Vec<serde_json::Value> = store.items.values()
        .filter(|i| i.game_id == game_id && !i.burned)
        .map(|i| serde_json::json!({
            "item_id": i.item_id,
            "name": i.name,
            "rarity": i.rarity.to_string(),
            "owner": i.owner,
            "category": i.category,
        }))
        .collect();

    // Aktive Listings
    let active_listings: Vec<serde_json::Value> = store.listings.values()
        .filter(|l| l.status == stone::token::game_economy::ListingStatus::Active)
        .filter_map(|l| {
            store.items.get(&l.item_id).filter(|i| i.game_id == game_id).map(|i| {
                serde_json::json!({
                    "listing_id": l.listing_id,
                    "item": i.name,
                    "price": l.price.to_string(),
                    "seller": l.seller,
                })
            })
        })
        .collect();

    // Shop-Items (Katalog)
    let shop_items: Vec<serde_json::Value> = store.shop_items.values()
        .filter(|si| si.game_id == game_id && si.active)
        .map(|si| serde_json::json!({
            "shop_item_id": si.shop_item_id,
            "name": si.name,
            "price": si.price.to_string(),
            "stock": si.stock,
            "sold": si.sold,
        }))
        .collect();

    // Letzte Audit-Einträge
    let audit = store.audit_log_for_game(&game_id, 20);

    Json(serde_json::json!({
        "ok": true,
        "game": {
            "game_id": game.game_id,
            "name": game.name,
            "description": game.description,
            "website": game.website,
            "status": game.status,
            "permissions": game.permissions,
            "genres": game.genres,
            "created_at": game.created_at,
        },
        "developer_wallet": game.developer_wallet,
        "developer_balance": dev_balance.to_string(),
        "treasury_wallet": treasury_addr,
        "treasury_balance": treasury_balance.to_string(),
        "player_count": player_wallets.len(),
        "players": player_wallets,
        "items_count": items.len(),
        "items": items,
        "active_listings": active_listings,
        "shop_items": shop_items,
        "recent_audit": audit,
    })).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §10 IN-GAME SHOP – Memo-basierter Item-Kauf
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct ShopBuyReq {
    pub mnemonic: String,
    pub game_id: String,
    pub shop_item_id: String,
    pub quantity: Option<u64>,
}

/// POST /api/v1/sdk/shop/buy – Item aus dem Game-Shop kaufen.
///
/// Flow: Spieler sendet Stone an die Treasury-Wallet des Spiels.
/// Die TX enthält ein Memo mit `shop:{game_id}:{shop_item_id}:{qty}`.
/// Nach Mempool-Akzeptanz wird das Item sofort an den Spieler ausgeliefert.
pub async fn handle_sdk_shop_buy(
    State(state): State<AppState>,
    Json(req): Json<ShopBuyReq>,
) -> impl IntoResponse {
    if !crate::server::auth_middleware::mnemonic_auth_enabled() {
        return (axum::http::StatusCode::GONE, axum::Json(
            crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_shop_buy")
        )).into_response();
    }
    crate::server::auth_middleware::log_mnemonic_call("handle_sdk_shop_buy");
    let wallet = match Wallet::from_mnemonic(&req.mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };
    let qty = req.quantity.unwrap_or(1).max(1).min(100);

    // Shop-Item prüfen
    let (price, item_name, treasury_addr, item_rarity, item_category) = {
        let store = read_game_store(&state);
        let shop_item = match store.shop_items.get(&req.shop_item_id) {
            Some(si) if si.game_id == req.game_id && si.active => si.clone(),
            Some(_) => return (StatusCode::BAD_REQUEST, err_json("Shop-Item nicht verfügbar")).into_response(),
            None => return (StatusCode::NOT_FOUND, err_json("Shop-Item nicht gefunden")).into_response(),
        };
        if let Some(stock) = shop_item.stock {
            if shop_item.sold >= stock {
                return (StatusCode::CONFLICT, err_json("Ausverkauft")).into_response();
            }
        }
        let game = match store.registered_games.get(&req.game_id) {
            Some(g) => g.clone(),
            None => return (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
        };
        let treasury = derive_game_wallet(&game.developer_wallet, &req.game_id);
        (
            shop_item.price * Decimal::from(qty),
            shop_item.name.clone(),
            treasury,
            shop_item.rarity.clone(),
            shop_item.category.clone(),
        )
    };

    // Balance prüfen
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.balance(&wallet.address()) < price {
            return (StatusCode::BAD_REQUEST, err_json(&format!(
                "Nicht genug STONE: benötigt {price}, verfügbar {}",
                ledger.balance(&wallet.address())
            ))).into_response();
        }
    }

    let memo = format!("shop:{}:{}:{}", req.game_id, req.shop_item_id, qty);

    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&wallet.address()) + state.node.mempool.sender_pending_count(&wallet.address())
    };

    let tx = match wallet.sign_tx_with_tier(
        TxType::Transfer, treasury_addr.clone(), price, nonce,
        memo.clone(),
        stone::token::FeeTier::Priority,
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response(),
    };

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(_) => {
            broadcast_tx(&state, tx.clone());

            // Item an Spieler ausliefern + sold counter hochzählen
            let delivered_items = with_game_store_mut(&state, |store| {
                // Stock updaten
                if let Some(si) = store.shop_items.get_mut(&req.shop_item_id) {
                    si.sold += qty;
                }
                // NFT-Items minten und an Spieler geben
                let mut item_ids = Vec::new();
                for _ in 0..qty {
                    let item_id = format!("shop-{}-{}", req.shop_item_id, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let item = stone::token::game_economy::GameItem {
                        item_id: item_id.clone(),
                        name: item_name.clone(),
                        description: format!("Gekauft aus dem Shop von {}", req.game_id),
                        category: item_category.clone(),
                        rarity: item_rarity.clone(),
                        owner: wallet.address(),
                        game_id: req.game_id.clone(),
                        creator: treasury_addr.clone(),
                        metadata: std::collections::HashMap::new(),
                        created_at: chrono::Utc::now().timestamp(),
                        transferable: true,
                        burned: false,
                    };
                    store.items.insert(item_id.clone(), item);
                    item_ids.push(item_id);
                }
                store.audit(&req.game_id, &wallet.address(), "shop_buy", serde_json::json!({
                    "shop_item_id": req.shop_item_id,
                    "quantity": qty,
                    "price": price.to_string(),
                    "items": item_ids,
                }), true);
                item_ids
            });

            Json(serde_json::json!({
                "ok": true,
                "tx_id": tx.tx_id,
                "shop_item_id": req.shop_item_id,
                "item_name": item_name,
                "quantity": qty,
                "price": price.to_string(),
                "treasury": treasury_addr,
                "memo": memo,
                "items_delivered": delivered_items,
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response(),
    }
}

// ── Shop-Catalog Management (Developer-only) ────────────────────────────────

#[derive(Deserialize)]
pub struct ShopItemCreateReq {
    pub shop_item_id: String,
    pub name: String,
    pub description: Option<String>,
    pub price: String,
    pub stock: Option<u64>,
    pub category: Option<String>,
    pub rarity: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// POST /api/v1/sdk/shop/item – Neues Item im Shop anlegen (X-SDK-Key nötig)
pub async fn handle_sdk_shop_create_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ShopItemCreateReq>,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    let price: Decimal = match req.price.parse() {
        Ok(p) if p > Decimal::ZERO => p,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Preis")).into_response(),
    };

    if req.shop_item_id.len() < 2 || req.shop_item_id.len() > 64 {
        return (StatusCode::BAD_REQUEST, err_json("shop_item_id muss 2-64 Zeichen sein")).into_response();
    }

    let rarity = match req.rarity.as_deref() {
        Some("common") | None => stone::token::game_economy::ItemRarity::Common,
        Some("uncommon") => stone::token::game_economy::ItemRarity::Uncommon,
        Some("rare") => stone::token::game_economy::ItemRarity::Rare,
        Some("epic") => stone::token::game_economy::ItemRarity::Epic,
        Some("legendary") => stone::token::game_economy::ItemRarity::Legendary,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültige Rarität")).into_response(),
    };

    let result = with_game_store_mut(&state, |store| {
        if store.shop_items.contains_key(&req.shop_item_id) {
            return Err("Shop-Item existiert bereits".to_string());
        }
        let item = stone::token::game_economy::ShopItem {
            shop_item_id: req.shop_item_id.clone(),
            game_id: game_id.clone(),
            name: req.name.clone(),
            description: req.description.clone().unwrap_or_default(),
            price,
            stock: req.stock,
            sold: 0,
            category: req.category.clone().unwrap_or_else(|| "general".to_string()),
            rarity,
            metadata: req.metadata.clone().unwrap_or(serde_json::json!({})),
            active: true,
            created_at: chrono::Utc::now().timestamp(),
            price_mode: None,
        };
        store.shop_items.insert(req.shop_item_id.clone(), item);
        store.audit(&game_id, "developer", "shop_create_item", serde_json::json!({
            "shop_item_id": req.shop_item_id,
            "name": req.name,
            "price": price.to_string(),
            "stock": req.stock,
        }), true);
        // Owner-Aktivität → Heartbeat (verhindert Dormancy/Fork-Eligibility).
        let owner = store.registered_games.get(&game_id)
            .map(|g| g.developer_wallet.clone());
        if let Some(o) = owner {
            store.touch_owner_heartbeat(&game_id, &o);
        }
        Ok(())
    });

    match result {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "shop_item_id": req.shop_item_id,
            "name": req.name,
            "price": price.to_string(),
            "stock": req.stock,
        })).into_response(),
        Err(e) => (StatusCode::CONFLICT, err_json(&e)).into_response(),
    }
}

/// GET /api/v1/sdk/shop/catalog?game_id=... – Shop-Katalog eines Spiels (öffentlich)
pub async fn handle_sdk_shop_catalog(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<GameIdQuery>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let items: Vec<serde_json::Value> = store.shop_items.values()
        .filter(|si| si.game_id == q.game_id && si.active)
        .map(|si| {
            let remaining = si.stock.map(|s| s.saturating_sub(si.sold));
            serde_json::json!({
                "shop_item_id": si.shop_item_id,
                "name": si.name,
                "description": si.description,
                "price": si.price.to_string(),
                "category": si.category,
                "rarity": si.rarity.to_string(),
                "stock": si.stock,
                "remaining": remaining,
                "sold": si.sold,
                "metadata": si.metadata,
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "game_id": q.game_id,
        "count": items.len(),
        "items": items,
    }))
}

#[derive(Deserialize)]
pub struct GameIdQuery {
    pub game_id: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  §X SIGNED-TX-SUBMIT – Client-Side-Signing Migration-Endpoint
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/v1/sdk/tx/submit ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubmitSignedTxReq {
    /// Vollständig signierte TokenTx (Client-Side erstellt, z.B. via Stone-SDK
    /// oder `Wallet::sign_tx`). Der Mnemonic darf nicht im Request stehen.
    pub tx: TokenTx,
}

/// POST /api/v1/sdk/tx/submit – Generischer Mempool-Submit für signierte TXs.
///
/// **Architektur**: Migrations-Endpoint für Client-Side-Signing. Ersetzt
/// schrittweise die Mnemonic-basierten Endpoints (`/sdk/tx/buy-item`,
/// `/sdk/tx/sell-item`, `/sdk/tx/transfer`, `/sdk/tx/batch`). SDK-Clients
/// signieren die TX lokal mit dem User-Wallet und senden ausschließlich die
/// fertige, signierte Transaktion.
///
/// **Auth**: SDK-API-Key via `X-SDK-Key` Header.
///
/// **Erlaubte TX-Typen** (Whitelist):
/// - `Transfer`  — Coins zwischen Spielern
/// - `Burn`      — Item/Coin verbrennen
/// - `HtlcCreate` / `HtlcClaim` / `HtlcRefund` — Cross-Chain Bridge
///
/// **Blockiert** (eigene Pfade vorhanden):
/// - `Stake`/`Unstake`/`Delegate`/`Undelegate` → `/api/v1/mining/*`
/// - `Mint`/`Reward`/`Memorial` → server-trusted, nur intern
/// - `RotateKey` → `/api/v1/token/transfer` (rate-limited)
/// - `AccountRegister`/`AccountUpdate` → eigene Auth-Endpoints
/// - `ChatMessage` → `/api/v1/chat/*` (Spam-Filter)
/// - `Onboard` → server-trusted
pub async fn handle_sdk_tx_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SubmitSignedTxReq>,
) -> impl IntoResponse {
    // 1. SDK-Auth
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(g) => g,
        Err((sc, j)) => return (sc, j).into_response(),
    };

    let tx = req.tx;

    // 2. TX-Typ-Whitelist
    match tx.tx_type {
        TxType::Transfer
        | TxType::Burn
        | TxType::HtlcCreate
        | TxType::HtlcClaim
        | TxType::HtlcRefund => {}
        other => {
            return (
                StatusCode::BAD_REQUEST,
                err_json(&format!(
                    "TX-Typ {:?} nicht über /sdk/tx/submit erlaubt. \
                     Erlaubt: Transfer, Burn, HtlcCreate/Claim/Refund.",
                    other
                )),
            ).into_response();
        }
    }

    // 3. Pool-Accounts blockieren (nur server-interner Pfad)
    if tx.from.starts_with("pool:") {
        return (
            StatusCode::FORBIDDEN,
            err_json("Pool-Konten dürfen nicht über SDK eingereicht werden."),
        ).into_response();
    }

    // 4. Volle TX-Validierung inkl. Signatur-Prüfung (Client-Side-Signing!)
    if let Err(e) = stone::token::validate_tx(&tx) {
        return (
            StatusCode::BAD_REQUEST,
            err_json(&format!("TX-Validierung fehlgeschlagen: {e}")),
        ).into_response();
    }

    // 5. TX-ID Konsistenz: Client darf keine fremde tx_id setzen
    let expected_id = stone::token::compute_tx_id(&tx);
    if !tx.tx_id.is_empty() && tx.tx_id != expected_id {
        return (
            StatusCode::BAD_REQUEST,
            err_json("tx_id stimmt nicht mit Hash überein"),
        ).into_response();
    }

    // 6. Rate-Limiting per Sender (gleicher Bucket wie /token/transfer)
    let rate_key = tx.from.clone();
    if !state.rate_limits.transfer.check(&rate_key) {
        let retry = state.rate_limits.transfer.retry_after_secs(&rate_key);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("Rate Limit überschritten. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        ).into_response();
    }

    // 7. Mempool-Submit
    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            broadcast_tx(&state, tx.clone());
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "ok": true,
                    "status": "pending",
                    "tx_id": if tx.tx_id.is_empty() { expected_id } else { tx.tx_id.clone() },
                    "game_id": game_id,
                    "tx_type": format!("{:?}", tx.tx_type),
                    "mempool_size": state.node.mempool.pending_count(),
                })),
            ).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            err_json(&format!("Mempool: {e}")),
        ).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GAME FORKS & OWNERSHIP TRANSFER
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Lebenszyklus eines Spiels (vereinfacht):
//
//      Active ──(30d ohne Owner-Heartbeat)──▶ Dormant
//      Dormant ──(weitere 60d)──▶ Abandoned
//      Abandoned ──(Fork-Antrag + 14d Challenge + Finalize)──▶ Forked
//
//  Endpunkte:
//      POST /api/v1/sdk/game/transfer-ownership   – friedliche Übergabe
//      POST /api/v1/sdk/game/fork/propose         – Fork-Antrag stellen
//      POST /api/v1/sdk/game/fork/challenge       – Gegenbieten
//      POST /api/v1/sdk/game/fork/cancel          – Owner-Veto (Owner zurück)
//      POST /api/v1/sdk/game/fork/finalize        – nach Ablauf finalisieren
//      GET  /api/v1/sdk/game/{game_id}/forks      – alle Anträge zu diesem Spiel
//      GET  /api/v1/sdk/game/{game_id}/status     – effektiver Status inkl. Dormancy
//
//  Auth: Owner-Aktionen über `owner_mnemonic` (wie übrige SDK-Endpoints).
//        Claimant/Challenger über `mnemonic` (signiert sich selbst).
//
//  Bond-Escrow im Ledger ist **noch nicht** integriert (separate Phase):
//  Stake wird hier nur als State erfasst, das Locken erfolgt später über
//  Pool-Transfer pool:fork:<new_game_id>.
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct TransferOwnershipReq {
    pub owner_mnemonic: String,
    pub game_id: String,
    /// Hex-Pubkey ODER `stone1...` Bech32m-Adresse des neuen Owners.
    pub new_owner: String,
}

/// POST /api/v1/sdk/game/transfer-ownership – Owner übergibt das Spiel.
pub async fn handle_sdk_game_transfer_ownership(
    State(state): State<AppState>,
    Json(req): Json<TransferOwnershipReq>,
) -> impl IntoResponse {
    let owner = match Wallet::from_mnemonic(&req.owner_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Owner-Mnemonic: {e}"))).into_response(),
    };
    let new_owner_hex = match stone::token::address::normalize_to_hex(&req.new_owner) {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST,
            err_json("new_owner: weder 64-Hex noch stone1...-Adresse")).into_response(),
    };
    let result = with_game_store_mut(&state, |store| {
        store.transfer_ownership(&req.game_id, &owner.address(), &new_owner_hex)
    });
    match result {
        Ok(()) => Json(serde_json::json!({
            "ok": true, "game_id": req.game_id, "new_owner": new_owner_hex,
        })).into_response(),
        Err(e) => fork_err_response(e),
    }
}

#[derive(Deserialize)]
pub struct ForkProposeReq {
    /// Mnemonic des Antragstellers (zahlt den Bond).
    pub claimant_mnemonic: String,
    pub predecessor_game_id: String,
    pub new_game_id: String,
    pub new_name: String,
    /// Bond in STONE (Mindest: 1000).
    pub stake_amount: String,
}

/// POST /api/v1/sdk/game/fork/propose – Fork-Antrag für ein verlassenes Spiel.
///
/// Ablauf:
///   1. Balance-Check (Stake + Standard-Fee muss verfügbar sein).
///   2. Proposal anlegen (deterministischer Bond-Pool wird zugewiesen).
///   3. Claimant signiert Transfer(`stake`) → `bond_pool`, TX ins Mempool.
///   4. tx_id wird in `proposal.bond_tx_ids[claimant_pubkey]` gespeichert.
///
/// Schlägt der Mempool-Submit fehl, wird das Proposal wieder entfernt.
pub async fn handle_sdk_game_fork_propose(
    State(state): State<AppState>,
    Json(req): Json<ForkProposeReq>,
) -> impl IntoResponse {
    let claimant = match Wallet::from_mnemonic(&req.claimant_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };
    let stake: Decimal = match req.stake_amount.parse() {
        Ok(s) if s > Decimal::ZERO => s,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger stake_amount")).into_response(),
    };

    // 1) Balance-Check vor State-Mutation.
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let bal = ledger.balance(&claimant.address());
        if bal < stake {
            return (StatusCode::BAD_REQUEST, err_json(&format!(
                "Nicht genug STONE: benötigt {stake}, verfügbar {bal}"
            ))).into_response();
        }
    }

    let now = chrono::Utc::now().timestamp();

    // 2) Proposal anlegen.
    let proposal = match with_game_store_mut(&state, |store| {
        store.propose_fork(
            &req.predecessor_game_id,
            &req.new_game_id,
            &req.new_name,
            &claimant.address(),
            stake,
            now,
        )
    }) {
        Ok(p) => p,
        Err(e) => return fork_err_response(e),
    };

    // 3) Bond-TX signieren und ins Mempool.
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&claimant.address()) + state.node.mempool.sender_pending_count(&claimant.address())
    };
    let tx = match claimant.sign_tx_with_tier(
        TxType::Transfer, proposal.bond_pool.clone(), stake, nonce,
        format!("Fork-Bond: {} → {}", req.predecessor_game_id, req.new_game_id),
        stone::token::FeeTier::Standard,
    ) {
        Ok(t) => t,
        Err(e) => {
            // Proposal rückgängig.
            with_game_store_mut(&state, |store| {
                store.fork_proposals.remove(&proposal.proposal_id);
            });
            return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response();
        }
    };

    let submit_result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };
    if let Err(e) = submit_result {
        with_game_store_mut(&state, |store| {
            store.fork_proposals.remove(&proposal.proposal_id);
        });
        return (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response();
    }
    broadcast_tx(&state, tx.clone());

    // 4) Bond-TX-ID am Proposal vermerken.
    with_game_store_mut(&state, |store| {
        let _ = store.record_fork_bond_tx(&proposal.proposal_id, &claimant.address(), &tx.tx_id);
    });

    Json(serde_json::json!({
        "ok": true,
        "proposal": proposal,
        "bond_tx_id": tx.tx_id,
        "bond_pool": proposal.bond_pool,
    })).into_response()
}

#[derive(Deserialize)]
pub struct ForkChallengeReq {
    pub challenger_mnemonic: String,
    pub proposal_id: String,
    pub stake_amount: String,
}

/// POST /api/v1/sdk/game/fork/challenge – Konkurrenz-Bid auf bestehenden Antrag.
///
/// Ablauf analog zu `propose`: Balance-Check → store.challenge_fork() →
/// Transfer(`stake`) → `bond_pool` → record_fork_bond_tx.
pub async fn handle_sdk_game_fork_challenge(
    State(state): State<AppState>,
    Json(req): Json<ForkChallengeReq>,
) -> impl IntoResponse {
    let challenger = match Wallet::from_mnemonic(&req.challenger_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Mnemonic: {e}"))).into_response(),
    };
    let stake: Decimal = match req.stake_amount.parse() {
        Ok(s) if s > Decimal::ZERO => s,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger stake_amount")).into_response(),
    };

    // Bond-Pool aus Proposal holen + Balance-Check.
    let bond_pool = match {
        let store = read_game_store(&state);
        store.fork_bond_pool(&req.proposal_id)
    } {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, err_json("Fork-Antrag nicht gefunden")).into_response(),
    };
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let bal = ledger.balance(&challenger.address());
        if bal < stake {
            return (StatusCode::BAD_REQUEST, err_json(&format!(
                "Nicht genug STONE: benötigt {stake}, verfügbar {bal}"
            ))).into_response();
        }
    }

    let now = chrono::Utc::now().timestamp();
    // Vorherigen Stake merken, falls Rollback nötig.
    let prev_stake = {
        let store = read_game_store(&state);
        store.fork_proposals.get(&req.proposal_id)
            .and_then(|p| p.challengers.get(&challenger.address()).cloned())
    };

    let challenge_result = with_game_store_mut(&state, |store| {
        store.challenge_fork(&req.proposal_id, &challenger.address(), stake, now)
    });
    if let Err(e) = challenge_result {
        return fork_err_response(e);
    }

    // Bond-TX signieren + Mempool.
    let nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&challenger.address()) + state.node.mempool.sender_pending_count(&challenger.address())
    };
    let tx = match challenger.sign_tx_with_tier(
        TxType::Transfer, bond_pool.clone(), stake, nonce,
        format!("Fork-Bond Challenge: {}", req.proposal_id),
        stone::token::FeeTier::Standard,
    ) {
        Ok(t) => t,
        Err(e) => {
            // State-Rollback: vorherigen Stake wiederherstellen.
            let pid = req.proposal_id.clone();
            let addr = challenger.address();
            with_game_store_mut(&state, |store| {
                if let Some(p) = store.fork_proposals.get_mut(&pid) {
                    match prev_stake {
                        Some(s) => { p.challengers.insert(addr, s); }
                        None    => { p.challengers.remove(&addr); }
                    }
                }
            });
            return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("TX-Sign: {e}"))).into_response();
        }
    };
    let submit_result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };
    if let Err(e) = submit_result {
        let pid = req.proposal_id.clone();
        let addr = challenger.address();
        with_game_store_mut(&state, |store| {
            if let Some(p) = store.fork_proposals.get_mut(&pid) {
                match prev_stake {
                    Some(s) => { p.challengers.insert(addr, s); }
                    None    => { p.challengers.remove(&addr); }
                }
            }
        });
        return (StatusCode::BAD_REQUEST, err_json(&format!("Mempool: {e}"))).into_response();
    }
    broadcast_tx(&state, tx.clone());

    with_game_store_mut(&state, |store| {
        let _ = store.record_fork_bond_tx(&req.proposal_id, &challenger.address(), &tx.tx_id);
    });

    Json(serde_json::json!({
        "ok": true,
        "proposal_id": req.proposal_id,
        "stake": stake.to_string(),
        "bond_tx_id": tx.tx_id,
        "bond_pool": bond_pool,
    })).into_response()
}

#[derive(Deserialize)]
pub struct ForkCancelReq {
    pub owner_mnemonic: String,
    pub proposal_id: String,
}

/// POST /api/v1/sdk/game/fork/cancel – Owner-Veto bei zurückgekehrtem Owner.
pub async fn handle_sdk_game_fork_cancel(
    State(state): State<AppState>,
    Json(req): Json<ForkCancelReq>,
) -> impl IntoResponse {
    let owner = match Wallet::from_mnemonic(&req.owner_mnemonic) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, err_json(&format!("Owner-Mnemonic: {e}"))).into_response(),
    };
    let result = with_game_store_mut(&state, |store| {
        store.cancel_fork_by_owner(&req.proposal_id, &owner.address())
    });
    match result {
        Ok(()) => Json(serde_json::json!({ "ok": true, "proposal_id": req.proposal_id })).into_response(),
        Err(e) => fork_err_response(e),
    }
}

#[derive(Deserialize)]
pub struct ForkFinalizeReq {
    pub proposal_id: String,
}

/// POST /api/v1/sdk/game/fork/finalize – Antrag nach Ablauf der Challenge-Periode
/// abschließen. Auth-frei: rein zeitbasiert; jeder darf triggern.
///
/// Die Bonds verbleiben aktuell im `bond_pool`-Pseudo-Account:
/// - **Sieger**: Stake wird durch das 30-Tage-Vesting (`FORK_BOND_VEST_SECS`)
///   gesperrt; ein späterer Sweeper transferiert ihn an den Sieger zurück.
/// - **Verlierer**: ihre Bonds werden über einen separaten Refund-Job an die
///   Challenger zurückgegeben (Phase 2 – noch nicht implementiert).
///
/// Die Response enthält alle bond_tx_ids, damit Clients/Sweeper-Jobs den
/// Escrow-Stand verfolgen können.
pub async fn handle_sdk_game_fork_finalize(
    State(state): State<AppState>,
    Json(req): Json<ForkFinalizeReq>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    let result = with_game_store_mut(&state, |store| {
        store.finalize_fork(&req.proposal_id, now)
    });
    match result {
        Ok((game, api_key)) => {
            let (bond_pool, bond_tx_ids, winner) = {
                let store = read_game_store(&state);
                let p = store.fork_proposals.get(&req.proposal_id).cloned();
                match p {
                    Some(p) => (p.bond_pool, p.bond_tx_ids, game.developer_wallet.clone()),
                    None    => (String::new(), Default::default(), game.developer_wallet.clone()),
                }
            };
            Json(serde_json::json!({
                "ok": true,
                "proposal_id": req.proposal_id,
                "new_game": game,
                "api_key": api_key,
                "winner": winner,
                "bond_pool": bond_pool,
                "bond_tx_ids": bond_tx_ids,
                "vesting_secs": stone::token::game_economy::FORK_BOND_VEST_SECS,
                "vesting_until": now + stone::token::game_economy::FORK_BOND_VEST_SECS,
                "note": "Bonds bleiben im Pool – Vesting/Refund-Sweep ist Phase 2",
            })).into_response()
        }
        Err(e) => fork_err_response(e),
    }
}

/// GET /api/v1/sdk/game/{game_id}/forks – alle Fork-Anträge mit diesem Vorgänger.
pub async fn handle_sdk_game_forks_list(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let store = read_game_store(&state);
    let proposals: Vec<_> = store.fork_proposals.values()
        .filter(|p| p.predecessor_game_id == game_id)
        .cloned()
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "proposals": proposals,
    })).into_response()
}

/// GET /api/v1/sdk/game/{game_id}/status – effektiver Status (inkl. Dormancy-Compute).
pub async fn handle_sdk_game_effective_status(
    State(state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    let store = read_game_store(&state);
    let game = match store.get_game(&game_id) {
        Some(g) => g,
        None => return (StatusCode::NOT_FOUND, err_json("Spiel nicht gefunden")).into_response(),
    };
    let eff = store.effective_status(&game_id, now).unwrap_or(game.status.clone());
    Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "stored_status": game.status,
        "effective_status": eff,
        "last_owner_heartbeat": game.last_owner_heartbeat,
        "successor_of": game.successor_of,
        "inherited_game_ids": game.inherited_game_ids,
    })).into_response()
}

/// Einheitliche Fehler-Antwort für Fork/Heartbeat-Aktionen.
fn fork_err_response(e: stone::token::game_economy::GameEconomyError) -> axum::response::Response {
    use stone::token::game_economy::GameEconomyError as Ge;
    let code = match &e {
        Ge::Unauthorized { .. }           => StatusCode::FORBIDDEN,
        Ge::NotFound { .. }               => StatusCode::NOT_FOUND,
        Ge::AlreadyExists { .. }          => StatusCode::CONFLICT,
        Ge::GameAlreadyForked { .. }      => StatusCode::CONFLICT,
        Ge::ForkProposalActive { .. }     => StatusCode::CONFLICT,
        Ge::ForkChallengeOpen { .. }      => StatusCode::CONFLICT,
        Ge::GameNotAbandoned { .. }       => StatusCode::PRECONDITION_FAILED,
        Ge::InvalidState { .. }           => StatusCode::PRECONDITION_FAILED,
        Ge::InvalidAmount { .. }          => StatusCode::BAD_REQUEST,
        Ge::InvalidInput { .. }           => StatusCode::BAD_REQUEST,
        _                                 => StatusCode::BAD_REQUEST,
    };
    (code, err_json(&e.to_string())).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FORK BOND SWEEPER – Refund/Vesting-Auszahlung als System-TX
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct ForkSweepReq {
    pub proposal_id: String,
}

/// POST /api/v1/sdk/game/fork/sweep – zahlt fällige Bond-Anteile aus.
///
/// Auth-frei (zeitbasiert + State-validiert). Iteriert über
/// `store.plan_bond_sweep(...)`, baut je Empfänger eine `ForkBondRefund`-TX
/// (privileged System-TX, signaturfrei, analog `HtlcClaim`) und submittet
/// sie ins Mempool. Bei erfolgreichem Submit wird der Empfänger im Store
/// als ausgezahlt vermerkt → idempotent: weitere Sweeps für denselben
/// Pubkey sind No-Ops.
///
/// Reasons im Memo:
/// - `loser_refund` – sofort nach Finalize an Verlierer
/// - `winner_vest`  – nach 30 Tagen Vesting an den Sieger
/// - `owner_veto`   – nach `cancel_fork_by_owner` an alle Bewerber
pub async fn handle_sdk_game_fork_sweep(
    State(state): State<AppState>,
    Json(req): Json<ForkSweepReq>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    let plan = {
        let store = read_game_store(&state);
        match store.plan_bond_sweep(&req.proposal_id, now) {
            Ok(p) => p,
            Err(e) => return fork_err_response(e),
        }
    };
    let bond_pool = match {
        let store = read_game_store(&state);
        store.fork_bond_pool(&req.proposal_id)
    } {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, err_json("Fork-Antrag nicht gefunden")).into_response(),
    };

    if plan.is_empty() {
        return Json(serde_json::json!({
            "ok": true, "proposal_id": req.proposal_id,
            "swept": [],
            "note": "Nichts zu sweepen – entweder noch offen, im Vesting oder bereits ausgezahlt",
        })).into_response();
    }

    let mut results: Vec<serde_json::Value> = Vec::new();
    for (recipient, amount, reason) in plan {
        let memo = serde_json::json!({
            "proposal_id": req.proposal_id,
            "reason":      reason,
        }).to_string();
        let mut tx = TokenTx {
            tx_id:     String::new(),
            tx_type:   TxType::ForkBondRefund,
            from:      bond_pool.clone(),
            to:        recipient.clone(),
            amount,
            fee:       Decimal::ZERO,
            nonce:     0,
            timestamp: now,
            signature: "fork-bond-refund".to_string(),
            memo,
            chain_id:  default_chain_id(),
            fee_tier:  stone::token::FeeTier::Standard,
            signed_by: None,
        };
        tx.tx_id = compute_tx_id(&tx);
        let tx_id = tx.tx_id.clone();

        let submit = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(tx.clone(), Some(&ledger))
        };
        match submit {
            Ok(()) => {
                broadcast_tx(&state, tx.clone());
                with_game_store_mut(&state, |store| {
                    let _ = store.mark_bond_refunded(&req.proposal_id, &recipient);
                });
                results.push(serde_json::json!({
                    "recipient": recipient,
                    "amount":    amount.to_string(),
                    "reason":    reason,
                    "tx_id":     tx_id,
                    "status":    "submitted",
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "recipient": recipient,
                    "amount":    amount.to_string(),
                    "reason":    reason,
                    "status":    "failed",
                    "error":     e.to_string(),
                }));
            }
        }
    }

    Json(serde_json::json!({
        "ok":          true,
        "proposal_id": req.proposal_id,
        "bond_pool":   bond_pool,
        "swept":       results,
    })).into_response()
}

// ── POST /api/v1/sdk/game/play-drop ──────────────────────────────────────────
//
// Proof-of-Play: Game-Server meldet ein Drop-Event (z. B. Block-Break in Minecraft).
// Tokenomics-Modell 3 (70/20/10):
//   - 70% → Player-Wallet
//   - 20% → Game-Owner (developer_wallet, registriert)
//   - 10% → Foundation-Treasury (`pool:treasury`)
// Alle drei TXs werden vom **Foundation-Gaming-Wallet** signiert
// (`STONE_GAMING_POOL_MNEMONIC` oder pro Spiel verschlüsselt gespeichert).
// Auth bevorzugt per `X-SDK-Key`; `server_wallet_mnemonic` ist nur Legacy-Fallback.

#[derive(Deserialize)]
pub struct PlayDropReq {
    pub game_id: String,
    #[serde(default)]
    pub server_wallet_mnemonic: Option<String>,
    pub player_wallet: String,
    /// Drop-Betrag in STONE (z. B. "0.05").
    pub amount: String,
    /// Eindeutige Drop-ID (Idempotenz-Hint, vom Plugin generiert).
    #[serde(default)]
    pub drop_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn handle_sdk_play_drop(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PlayDropReq>,
) -> impl IntoResponse {
    // 1) Auth: bevorzugt per X-SDK-Key (API-Key-only Betrieb).
    // Legacy-Fallback: server_wallet_mnemonic im Body.
    let game_owner_addr = match validate_sdk_key(&state, &headers) {
        Ok(auth_game_id) => {
            if auth_game_id != req.game_id {
                return (StatusCode::FORBIDDEN,
                    err_json("X-SDK-Key gehört zu einem anderen game_id")).into_response();
            }
            let store = read_game_store(&state);
            // Play-Drop benötigt Basic-Permission (nicht Tournament — das ist für echte Turnierpreise)
            if !store.game_has_permission(&req.game_id, GamePermission::Basic) {
                return (StatusCode::FORBIDDEN,
                    err_json("Spiel hat keine 'basic' Berechtigung")).into_response();
            }
            match store.get_game(&req.game_id) {
                Some(g) => g.developer_wallet.clone(),
                None => return (StatusCode::NOT_FOUND,
                    err_json("Spiel nicht gefunden")).into_response(),
            }
        }
        // Legacy-Fallback nur wenn wirklich kein SDK-Header vorhanden ist.
        // Bei ungültigem Key soll der Request mit 403 enden (nicht als "Header fehlt" maskieren).
        Err((StatusCode::UNAUTHORIZED, _)) => {
        if !crate::server::auth_middleware::mnemonic_auth_enabled() {
            return (axum::http::StatusCode::GONE, axum::Json(
                crate::server::auth_middleware::mnemonic_killswitch_body("handle_sdk_play_drop")
            )).into_response();
        }
        crate::server::auth_middleware::log_mnemonic_call("handle_sdk_play_drop");

        let server_wallet_mnemonic = match req.server_wallet_mnemonic.as_ref() {
            Some(m) if !m.trim().is_empty() => m,
            _ => {
                return (StatusCode::UNAUTHORIZED,
                    err_json("SDK-Key Header fehlt (X-SDK-Key/X-API-Key, oder Legacy: server_wallet_mnemonic fehlt)")).into_response();
            }
        };
        let server_wallet = match Wallet::from_mnemonic(server_wallet_mnemonic) {
            Ok(w) => w,
            Err(e) => return (StatusCode::BAD_REQUEST,
                err_json(&format!("Server-Mnemonic: {e}"))).into_response(),
        };

        let store = read_game_store(&state);
        if !store.is_game_server_or_successor(&req.game_id, &server_wallet.address()) {
            return (StatusCode::FORBIDDEN, err_json(
                "Nicht der registrierte Game-Server (auch kein Nachfolger-Server)"
            )).into_response();
        }
        // Play-Drop benötigt Basic-Permission (nicht Tournament)
        if !store.game_has_permission(&req.game_id, GamePermission::Basic) {
            return (StatusCode::FORBIDDEN,
                err_json("Spiel hat keine 'basic' Berechtigung")).into_response();
        }
        match store.get_game(&req.game_id) {
            Some(g) => g.developer_wallet.clone(),
            None => return (StatusCode::NOT_FOUND,
                err_json("Spiel nicht gefunden")).into_response(),
        }
        }
        Err((sc, j)) => return (sc, j).into_response(),
    };

    // 2) Foundation Gaming-Wallet laden (Quelle der Auszahlungen)
    //    Priorität: 1) Pro-Spiel verschlüsselte Mnemonic auf Disk (App-Setup)
    //                2) Globale env STONE_GAMING_POOL_MNEMONIC (Legacy)
    let pool_mnemonic = if stone::gaming_pool::is_configured(&req.game_id) {
        let pass = stone::gaming_pool::resolve_data_passphrase();
        match stone::gaming_pool::load_pool_mnemonic(&req.game_id, &pass) {
            Ok(m) => m,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
                err_json(&format!("Gaming-Pool Entschlüsselung: {e}"))).into_response(),
        }
    } else {
        match std::env::var("STONE_GAMING_POOL_MNEMONIC") {
            Ok(m) if !m.trim().is_empty() => m,
            _ => return (StatusCode::SERVICE_UNAVAILABLE,
                err_json("Gaming-Pool nicht konfiguriert. Owner: per App POST /api/v1/sdk/owner/gaming-pool/configure (challenge-signiert) hinterlegen.")).into_response(),
        }
    };
    let pool_wallet = match Wallet::from_mnemonic(pool_mnemonic.trim()) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            err_json(&format!("Gaming-Pool Mnemonic: {e}"))).into_response(),
    };

    // 3) Betrag parsen + Cap-Check
    let amount_dec: Decimal = match req.amount.parse() {
        Ok(a) if a > Decimal::ZERO => a,
        _ => return (StatusCode::BAD_REQUEST, err_json("Ungültiger Betrag")).into_response(),
    };
    let amount_f64: f64 = amount_dec.to_string().parse().unwrap_or(0.0);
    if let Err(e) = state.play_drops.try_consume(
        &req.game_id, &req.player_wallet, amount_f64,
    ) {
        return (StatusCode::TOO_MANY_REQUESTS,
            err_json(&format!("Play-Drop abgelehnt: {e}"))).into_response();
    }

    // 4) 70/20/10 Split (8 Nachkommastellen, Rest geht an den Spieler)
    let pct_20 = (amount_dec * Decimal::new(20, 2)).round_dp(8);
    let pct_10 = (amount_dec * Decimal::new(10, 2)).round_dp(8);
    let player_amount = amount_dec - pct_20 - pct_10;
    let owner_amount = pct_20;
    let foundation_amount = pct_10;
    let foundation_addr = std::env::var("STONE_FOUNDATION_TREASURY_ADDR")
        .unwrap_or_else(|_| "pool:treasury".to_string());

    // 5) 3 Transfer-TXs sequentiell mit aufeinanderfolgenden Nonces signieren
    let base_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&pool_wallet.address())
            + state.node.mempool.sender_pending_count(&pool_wallet.address())
    };

    let drop_id = req.drop_id.clone().unwrap_or_else(|| "auto".into());
    let memo_base = req.reason.clone()
        .unwrap_or_else(|| format!("play_drop:{}:{}", req.game_id, drop_id));

    let mut txs: Vec<stone::token::TokenTx> = Vec::with_capacity(3);
    let recipients: Vec<(String, Decimal, &str)> = vec![
        (req.player_wallet.clone(), player_amount, "player"),
        (game_owner_addr.clone(),    owner_amount,  "owner"),
        (foundation_addr.clone(),    foundation_amount, "foundation"),
    ];
    for (i, (to, amt, tag)) in recipients.iter().enumerate() {
        if *amt <= Decimal::ZERO { continue; }
        let memo = format!("{memo_base}:{tag}");
        let tx = match pool_wallet.sign_tx_with_tier(
            TxType::Transfer,
            to.clone(),
            *amt,
            base_nonce + i as u64,
            memo,
            stone::token::FeeTier::Standard,
        ) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
                err_json(&format!("TX-Sign ({tag}): {e}"))).into_response(),
        };
        txs.push(tx);
    }

    // 6) Atomar in Mempool: bei Fehler in TX-2/3 vorherige nicht entfernen
    //    (best-effort — Mempool macht eigene Validierung)
    let mut accepted = Vec::with_capacity(txs.len());
    for tx in &txs {
        let res = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(tx.clone(), Some(&ledger))
        };
        if let Err(e) = res {
            return (StatusCode::BAD_REQUEST,
                err_json(&format!("Mempool ({} accepted, dann Fehler): {e}", accepted.len())))
                .into_response();
        }
        accepted.push(tx.tx_id.clone());
        broadcast_tx(&state, tx.clone());
    }

    with_game_store_mut(&state, |store| {
        store.audit(&req.game_id, &req.player_wallet, "play_drop",
            serde_json::json!({
                "amount": amount_dec.to_string(),
                "split": {
                    "player": player_amount.to_string(),
                    "owner": owner_amount.to_string(),
                    "foundation": foundation_amount.to_string(),
                },
                "drop_id": req.drop_id,
            }), true);
        store.touch_owner_heartbeat(&req.game_id, &game_owner_addr);
    });
    let (game_total, _) = state.play_drops.snapshot(&req.game_id);

    Json(serde_json::json!({
        "ok": true,
        "tx_ids": accepted,
        "player": req.player_wallet,
        "owner":  game_owner_addr,
        "foundation": foundation_addr,
        "amount": amount_dec.to_string(),
        "split": {
            "player": player_amount.to_string(),
            "owner":  owner_amount.to_string(),
            "foundation": foundation_amount.to_string(),
        },
        "drop_id": req.drop_id,
        "game_total_today": game_total,
    })).into_response()
}

// ── POST /api/v1/sdk/game/play-sell ──────────────────────────────────────────
//
// PoolCoin Auto-Sell: Spieler hat 20+ PoolCoins gesammelt → verkauft sie.
// Tokenomics (80/20):
//   - 80% PoolCoins → Recycling zurück in den Server-Pool (keine STONE-Auszahlung)
//   - 20% PoolCoins → STONE via Gaming-Pool mit 70/20/10 Split
//
// Der Pool stabilisiert sich selbst: hohe Sell-Volumen bedeuten mehr Recycling
// und mehr STONE-Auszahlungen, aber der 80%-Anteil hält den Pool gefüllt.

#[derive(Deserialize)]
pub struct PlaySellReq {
    pub game_id: String,
    pub player_wallet: String,
    /// Anzahl PoolCoins die verkauft werden sollen.
    pub pool_coins: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn handle_sdk_play_sell(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PlaySellReq>,
) -> impl IntoResponse {
    // Auth: SDK-Key erforderlich
    let game_owner_addr = match validate_sdk_key(&state, &headers) {
        Ok(gid) => {
            if gid != req.game_id {
                return (StatusCode::FORBIDDEN,
                    err_json("X-SDK-Key gehört zu einem anderen game_id")).into_response();
            }
            let store = read_game_store(&state);
            match store.get_game(&req.game_id) {
                Some(g) => g.developer_wallet.clone(),
                None => return (StatusCode::NOT_FOUND,
                    err_json("Spiel nicht gefunden")).into_response(),
            }
        }
        Err((sc, j)) => return (sc, j).into_response(),
    };

    if req.pool_coins == 0 || req.pool_coins > 10_000 {
        return (StatusCode::BAD_REQUEST,
            err_json("pool_coins muss zwischen 1 und 10.000 liegen")).into_response();
    }

    // 80/20 Split berechnen
    let total = Decimal::from(req.pool_coins);
    let recycling_coins = (total * Decimal::new(80, 2)).round_dp(0); // 80% zurück
    let stone_payout = total - recycling_coins; // 20% → STONE

    if stone_payout <= Decimal::ZERO {
        return (StatusCode::BAD_REQUEST, err_json("Nicht genug Coins für STONE-Payout (min. 5)")).into_response();
    }

    // STONE-Split: 70/20/10 aus dem Gaming-Pool
    // Quelle: pool:gaming (45M STONE) oder pro-Spiel Pool-Mnemonic
    let pool_mnemonic = if stone::gaming_pool::is_configured(&req.game_id) {
        let pass = stone::gaming_pool::resolve_data_passphrase();
        match stone::gaming_pool::load_pool_mnemonic(&req.game_id, &pass) {
            Ok(m) => m,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
                err_json(&format!("Pool: {e}"))).into_response(),
        }
    } else {
        match std::env::var("STONE_GAMING_POOL_MNEMONIC") {
            Ok(m) if !m.trim().is_empty() => m,
            _ => return (StatusCode::SERVICE_UNAVAILABLE,
                err_json("Gaming-Pool nicht konfiguriert")).into_response(),
        }
    };
    let pool_wallet = match Wallet::from_mnemonic(pool_mnemonic.trim()) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            err_json(&format!("Pool Mnemonic: {e}"))).into_response(),
    };

    // Balance-Check
    let pool_addr = pool_wallet.address();
    let pool_balance = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.balance(&pool_addr)
    };
    if pool_balance < stone_payout {
        return (StatusCode::SERVICE_UNAVAILABLE,
            err_json(&format!("Gaming-Pool hat nicht genug STONE: benötigt {stone_payout}, verfügbar {pool_balance}"))).into_response();
    }

    // 70/20/10 STONE-Split
    let pct_20 = (stone_payout * Decimal::new(20, 2)).round_dp(8);
    let pct_10 = (stone_payout * Decimal::new(10, 2)).round_dp(8);
    let player_amount = stone_payout - pct_20 - pct_10;
    let owner_amount = pct_20;
    let foundation_amount = pct_10;
    let foundation_addr = std::env::var("STONE_FOUNDATION_TREASURY_ADDR")
        .unwrap_or_else(|_| "pool:treasury".to_string());

    // TXs signieren
    let base_nonce = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        ledger.nonce(&pool_addr)
            + state.node.mempool.sender_pending_count(&pool_addr)
    };
    let memo_base = req.reason.clone().unwrap_or_else(|| format!("play_sell:{}", req.game_id));

    let mut tx_ids = Vec::with_capacity(3);
    let splits: Vec<(String, Decimal, &str)> = vec![
        (req.player_wallet.clone(), player_amount, "player"),
        (game_owner_addr.clone(), owner_amount, "owner"),
        (foundation_addr.clone(), foundation_amount, "foundation"),
    ];
    for (i, (to, amt, tag)) in splits.iter().enumerate() {
        if *amt <= Decimal::ZERO { continue; }
        let tx = match pool_wallet.sign_tx_with_tier(
            TxType::Transfer, to.clone(), *amt, base_nonce + i as u64,
            format!("{memo_base}:{tag}"),
            stone::token::FeeTier::Standard,
        ) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
                err_json(&format!("TX-Sign ({tag}): {e}"))).into_response(),
        };
        let tid = tx.tx_id.clone();
        let res = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            state.node.mempool.add_tx(tx.clone(), Some(&ledger))
        };
        if let Err(e) = res {
            return (StatusCode::BAD_REQUEST,
                err_json(&format!("Mempool ({tag}): {e}"))).into_response();
        }
        tx_ids.push(tid.clone());
        broadcast_tx(&state, tx.clone());
    }

    with_game_store_mut(&state, |store| {
        store.audit(&req.game_id, &req.player_wallet, "play_sell", serde_json::json!({
            "pool_coins": req.pool_coins,
            "recycled": recycling_coins.to_string(),
            "stone_payout": stone_payout.to_string(),
            "player_amount": player_amount.to_string(),
            "owner_amount": owner_amount.to_string(),
            "foundation_amount": foundation_amount.to_string(),
        }), true);
        store.touch_owner_heartbeat(&req.game_id, &game_owner_addr);
    });

    Json(serde_json::json!({
        "ok": true,
        "tx_ids": tx_ids,
        "pool_coins": req.pool_coins,
        "recycled": recycling_coins.to_string(),
        "stone_received": player_amount.to_string(),
        "owner_fee": owner_amount.to_string(),
        "player": req.player_wallet,
        "owner": game_owner_addr,
    })).into_response()
}

// ── GET /api/v1/sdk/game/pool/rate ───────────────────────────────────────────
//
// Dynamische Spawn-Rate basierend auf Pool-Füllstand.
// Plugin fragt diesen Endpoint, um die Drop-Chance anzupassen.

pub async fn handle_sdk_pool_rate(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let game_id = match q.get("game_id") {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return (StatusCode::BAD_REQUEST, err_json("game_id required")).into_response(),
    };

    // Pool-Balance ermitteln
    let pool_balance: Decimal = {
        let pool_mnemonic = if stone::gaming_pool::is_configured(&game_id) {
            let pass = stone::gaming_pool::resolve_data_passphrase();
            stone::gaming_pool::load_pool_mnemonic(&game_id, &pass).ok()
        } else {
            std::env::var("STONE_GAMING_POOL_MNEMONIC").ok()
        };
        match pool_mnemonic {
            Some(m) => {
                match Wallet::from_mnemonic(m.trim()) {
                    Ok(w) => {
                        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                        ledger.balance(&w.address())
                    }
                    Err(_) => Decimal::ZERO,
                }
            }
            None => Decimal::ZERO,
        }
    };

    // Dynamische Spawn-Rate: je niedriger der Pool, desto höher die Rate
    // Basis: 500 STONE als Normal-Schwelle
    let baseline = Decimal::new(500, 0); // 500 STONE
    let pool_fill_ratio = if baseline > Decimal::ZERO {
        (pool_balance / baseline).min(Decimal::ONE)
    } else {
        Decimal::ZERO
    };

    // Rate: 0.02 (leer) → 0.20 (voll)
    let spawn_rate = if pool_fill_ratio <= Decimal::from(1) / Decimal::from(4) {
        // < 25% → sehr häufig
        0.20f64
    } else if pool_fill_ratio <= Decimal::from(1) / Decimal::from(2) {
        // 25-50%
        0.10f64
    } else if pool_fill_ratio <= Decimal::from(3) / Decimal::from(4) {
        // 50-75%
        0.05f64
    } else {
        // > 75% → selten
        0.02f64
    };

    Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "pool_balance": pool_balance.to_string(),
        "pool_fill_ratio": format!("{:.2}", pool_fill_ratio),
        "spawn_rate": spawn_rate,
        "tier": if spawn_rate >= 0.20 { "very_high" }
                else if spawn_rate >= 0.10 { "high" }
                else if spawn_rate >= 0.05 { "normal" }
                else { "low" },
    })).into_response()
}

// ── GET /api/v1/sdk/game/play-drop/stats ─────────────────────────────────────

#[derive(Deserialize)]
pub struct PlayDropStatsReq {
    pub game_id: String,
}

pub async fn handle_sdk_play_drop_stats(
    State(state): State<AppState>,
    axum::extract::Query(req): axum::extract::Query<PlayDropStatsReq>,
) -> impl IntoResponse {
    let (total, per_player) = state.play_drops.snapshot(&req.game_id);
    let cfg = state.play_drops.config();
    Json(serde_json::json!({
        "ok": true,
        "game_id": req.game_id,
        "today": {
            "total": total,
            "per_player": per_player,
        },
        "limits": {
            "daily_game_cap":      cfg.daily_game_cap,
            "daily_player_cap":    cfg.daily_player_cap,
            "player_cooldown_secs": cfg.player_cooldown_secs,
            "max_drop_amount":     cfg.max_drop_amount,
        }
    })).into_response()
}

// ── GET /api/v1/sdk/game/pool/status ─────────────────────────────────────────
//
// Status des Foundation-Gaming-Pools (Quelle der Play-to-Earn Auszahlungen).
// Zeigt Adresse + verbleibende Balance + Initial-Allokation an.

pub async fn handle_sdk_play_drop_pool_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let foundation_addr = stone::token::foundation_gaming_address();
    let configured = foundation_addr.is_some();
    let initial: rust_decimal::Decimal = stone::token::genesis::GAMING_POOL_AMOUNT
        .parse()
        .unwrap_or(rust_decimal::Decimal::ZERO);

    let (foundation_balance, pool_balance) = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        let f = foundation_addr
            .as_deref()
            .map(|a| ledger.balance(a))
            .unwrap_or(rust_decimal::Decimal::ZERO);
        let p = ledger.balance(stone::token::genesis::POOL_GAMING);
        (f, p)
    };

    Json(serde_json::json!({
        "ok": true,
        "configured": configured,
        "foundation_address": foundation_addr,
        "initial_allocation": initial.to_string(),
        "foundation_balance": foundation_balance.to_string(),
        "pool_balance": pool_balance.to_string(),
        "split": {
            "player": "0.70",
            "owner":  "0.20",
            "foundation": "0.10",
        }
    })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Owner Gaming-Pool Setup (verschlüsselte Mnemonic on-Node)
//
// Flow:
//   1. POST /api/v1/sdk/owner/challenge   { game_id, action: "configure_gaming_pool" }
//   2. App signiert canonical_message mit dem Game-Owner-Key (Ed25519)
//   3. POST /api/v1/sdk/owner/gaming-pool/configure { game_id, challenge_id, signature, mnemonic }
//      → Server entschlüsselt nicht den Body (er kommt im Klartext über TLS),
//        verifiziert die Owner-Signatur und legt die Mnemonic AES-256-GCM-
//        verschlüsselt unter stone_data/gaming_pools/<game_id>.enc ab.
//   4. /play-drop nutzt diese Mnemonic ab sofort automatisch.

#[derive(Deserialize)]
pub struct GamingPoolConfigureReq {
    pub game_id: String,
    pub challenge_id: String,
    pub signature: String,
    pub mnemonic: String,
}

pub async fn handle_owner_gaming_pool_configure(
    State(_state): State<AppState>,
    Json(req): Json<GamingPoolConfigureReq>,
) -> impl IntoResponse {
    let _ = match consume_owner_challenge(
        &req.challenge_id, &req.game_id, "configure_gaming_pool", &req.signature
    ) {
        Ok(c) => c,
        Err((status, msg)) => return (status, err_json(&msg)).into_response(),
    };

    // Validierung: Mnemonic muss korrekt parsebar sein
    let pool_wallet = match Wallet::from_mnemonic(req.mnemonic.trim()) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST,
            err_json(&format!("Mnemonic ungültig: {e}"))).into_response(),
    };

    let pass = stone::gaming_pool::resolve_data_passphrase();
    if let Err(e) = stone::gaming_pool::save_pool(&req.game_id, req.mnemonic.trim(), &pass) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            err_json(&format!("Speichern fehlgeschlagen: {e}"))).into_response();
    }

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "game_id": req.game_id,
        "pool_address": pool_wallet.address(),
        "info": "Pool-Mnemonic ist jetzt verschlüsselt gespeichert. Plugin braucht nur noch X-SDK-Key.",
    }))).into_response()
}

#[derive(Deserialize)]
pub struct GamingPoolDeleteReq {
    pub game_id: String,
    pub challenge_id: String,
    pub signature: String,
}

pub async fn handle_owner_gaming_pool_delete(
    State(_state): State<AppState>,
    Json(req): Json<GamingPoolDeleteReq>,
) -> impl IntoResponse {
    if let Err((status, msg)) = consume_owner_challenge(
        &req.challenge_id, &req.game_id, "delete_gaming_pool", &req.signature
    ) {
        return (status, err_json(&msg)).into_response();
    }
    if let Err(e) = stone::gaming_pool::delete_pool(&req.game_id) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            err_json(&format!("Löschen fehlgeschlagen: {e}"))).into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "game_id": req.game_id }))).into_response()
}

/// POST /api/v1/sdk/owner/gaming-pool/refill
///
/// Owner-signierte Aktion: Füllt 500 STONE aus pool:founders in den Gaming-Pool.
/// Nur erlaubt wenn der Pool-Bestand 0 ist (One-Time Bootstrap).
#[derive(Deserialize)]
pub struct GamingPoolRefillReq {
    pub game_id: String,
    pub challenge_id: String,
    pub signature: String,
}

const POOL_REFILL_AMOUNT: &str = "500"; // 500 STONE initial fill

pub async fn handle_owner_gaming_pool_refill(
    State(state): State<AppState>,
    Json(req): Json<GamingPoolRefillReq>,
) -> impl IntoResponse {
    if let Err((status, msg)) = consume_owner_challenge(
        &req.challenge_id, &req.game_id, "configure_gaming_pool", &req.signature
    ) {
        return (status, err_json(&msg)).into_response();
    }

    // Pool-Adresse ermitteln
    let pool_addr = {
        if stone::gaming_pool::is_configured(&req.game_id) {
            let pass = stone::gaming_pool::resolve_data_passphrase();
            match stone::gaming_pool::load_pool_mnemonic(&req.game_id, &pass) {
                Ok(m) => match Wallet::from_mnemonic(m.trim()) {
                    Ok(w) => w.address(),
                    Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
                        err_json(&format!("Pool Wallet: {e}"))).into_response(),
                },
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
                    err_json(&format!("Pool Load: {e}"))).into_response(),
            }
        } else {
            return (StatusCode::PRECONDITION_FAILED,
                err_json("Gaming-Pool nicht konfiguriert")).into_response();
        }
    };

    // Prüfen ob Pool bereits Coins hat
    {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.balance(&pool_addr) > Decimal::ZERO {
            return (StatusCode::CONFLICT,
                err_json("Pool hat bereits Guthaben – Refill nur bei 0 STONE")).into_response();
        }
    }

    let amount: Decimal = POOL_REFILL_AMOUNT.parse().unwrap_or(Decimal::new(500, 0));

    // Transfer pool:founders → Pool-Wallet
    {
        let mut ledger = state.node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = ledger.system_pool_transfer("pool:founders", &pool_addr, amount) {
            return (StatusCode::INTERNAL_SERVER_ERROR,
                err_json(&format!("Transfer: {e}"))).into_response();
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "game_id": req.game_id,
        "amount": amount.to_string(),
        "pool_address": pool_addr,
    }))).into_response()
}

/// GET /api/v1/sdk/owner/gaming-pool/status?game_id=...
///
/// Auth: keine — die Antwort enthält nur Adresse + Balance, keine Geheimnisse.
pub async fn handle_owner_gaming_pool_status(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let game_id = match q.get("game_id") {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return (StatusCode::BAD_REQUEST, err_json("game_id required")).into_response(),
    };
    let configured = stone::gaming_pool::is_configured(&game_id);
    let mut pool_address: Option<String> = None;
    let mut pool_balance = rust_decimal::Decimal::ZERO;
    if configured {
        let pass = stone::gaming_pool::resolve_data_passphrase();
        if let Ok(m) = stone::gaming_pool::load_pool_mnemonic(&game_id, &pass) {
            if let Ok(w) = Wallet::from_mnemonic(m.trim()) {
                let addr = w.address();
                let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                pool_balance = ledger.balance(&addr);
                pool_address = Some(addr);
            }
        }
    }
    Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "configured": configured,
        "pool_address": pool_address,
        "pool_balance": pool_balance.to_string(),
    })).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Game Config – Plugin → Node → StoneScan Pipeline
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct GameConfigUploadReq {
    /// Game-ID (identisch zur SDK-Registrierung).
    pub game_id: String,
    /// Versions-String des Plugins.
    #[serde(default)]
    pub plugin_version: String,
    /// Drop-Konfiguration (optional).
    #[serde(default)]
    pub drops: Option<stone::game_config::DropTierConfig>,
    /// Mob-Drop-Konfiguration (optional).
    #[serde(default)]
    pub mobs: Option<stone::game_config::DropTierConfig>,
    /// Rare-Block-Konfiguration (optional).
    #[serde(default)]
    pub rare_block: Option<stone::game_config::RareBlockConfig>,
    /// Redeem-Limits (optional).
    #[serde(default)]
    pub redeem: Option<stone::game_config::RedeemConfig>,
    /// Scoreboard (optional).
    #[serde(default)]
    pub scoreboard: Option<stone::game_config::ScoreboardConfig>,
    /// Death-Protection (optional).
    #[serde(default)]
    pub death_protect: Option<stone::game_config::DeathProtectConfig>,
    /// Anti-Dupe-Scanner (optional).
    #[serde(default)]
    pub anti_dupe: Option<stone::game_config::AntiDupeConfig>,
}

/// POST /api/v1/sdk/game/config/upload
///
/// Authentifiziert: Game-Server lädt seine Plugin-Konfiguration hoch.
/// SDK-Key-Validierung stellt sicher, dass nur berechtigte Server schreiben.
///
/// Request-Body (JSON): `GameConfigUploadReq`
/// Response: `{ "ok": true, "game_id": "...", "stored": true }`
pub async fn handle_game_config_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GameConfigUploadReq>,
) -> impl IntoResponse {
    let game_id = match validate_sdk_key(&state, &headers) {
        Ok(gid) => gid,
        Err(resp) => return resp.into_response(),
    };

    // Game-ID im Body muss mit der aus dem SDK-Key übereinstimmen
    if req.game_id != game_id {
        return (
            StatusCode::BAD_REQUEST,
            err_json("game_id im Body stimmt nicht mit SDK-Key überein"),
        ).into_response();
    }

    let uploaded_by = {
        let store = read_game_store(&state);
        store.get_game(&game_id)
            .map(|g| g.developer_wallet.clone())
            .unwrap_or_default()
    };

    let now = chrono::Utc::now().timestamp();
    let cfg = stone::game_config::GameConfig {
        game_id: game_id.clone(),
        uploaded_at: now,
        uploaded_by,
        plugin_version: req.plugin_version,
        drops: req.drops,
        mobs: req.mobs,
        rare_block: req.rare_block,
        redeem: req.redeem,
        scoreboard: req.scoreboard,
        death_protect: req.death_protect,
        anti_dupe: req.anti_dupe,
    };

    if let Err(e) = stone::game_config::validate_config(&cfg) {
        return (StatusCode::BAD_REQUEST, err_json(&e)).into_response();
    }

    if let Err(e) = stone::game_config::save_config(&cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, err_json(&format!("Speichern: {e}"))).into_response();
    }

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "stored": true,
        "uploaded_at": now,
    }))).into_response()
}

/// GET /api/v1/games/{game_id}/config
///
/// Öffentlich lesbar: Gibt die letzte vom Plugin hochgeladene Konfiguration zurück.
/// Kein Auth nötig — die Konfiguration enthält keine Secrets.
pub async fn handle_game_config_read(
    State(_state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    match stone::game_config::load_config(&game_id) {
        Some(cfg) => {
            let is_fresh = stone::game_config::is_config_fresh(&game_id, 86400); // 24h
            Json(serde_json::json!({
                "ok": true,
                "game_id": game_id,
                "config": cfg,
                "fresh": is_fresh,
            })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            err_json(&format!("Keine Konfiguration für '{}' hinterlegt", game_id)),
        ).into_response(),
    }
}

/// GET /api/v1/games/{game_id}/config/history
///
/// Öffentlich: Gibt die Config-Historie zurück (letzte 10 Versionen).
/// Erlaubt Transparenz über Konfigurations-Änderungen.
pub async fn handle_game_config_history(
    State(_state): State<AppState>,
    Path(game_id): Path<String>,
) -> impl IntoResponse {
    let history = stone::game_config::load_config_history(&game_id);
    Json(serde_json::json!({
        "ok": true,
        "game_id": game_id,
        "count": history.len(),
        "history": history,
    })).into_response()
}
