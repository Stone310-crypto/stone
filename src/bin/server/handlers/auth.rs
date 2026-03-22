//! Auth handlers: signup, login, sync-users, push_user_to_peers, challenge-response, QR-login.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use stone::{
    auth::{
        create_user_with_phrase, generate_session_token, resolve_phrase, save_users,
        verify_challenge_signature, User, QR_LOGIN_TTL_SECS, SESSION_TOKEN_TTL_SECS,
    },
    master_node::PeerInfo,
};

use super::super::auth_middleware::{require_admin, require_user};
use super::super::rate_limiter::{check_rate_limit_tuple, extract_client_ip};
use super::super::state::AppState;

#[derive(Deserialize)]
pub struct SignupRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct LoginPhraseRequest {
    pub phrase: String,
}

/// POST /api/v1/auth/signup
pub async fn handle_signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<SignupRequest>,
) -> impl IntoResponse {
    // Rate Limiting: per IP
    let ip = extract_client_ip(&headers);
    if let Some(resp) = check_rate_limit_tuple(&state.rate_limits.auth_signup, &ip, "Signup") {
        return resp;
    }

    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Name darf nicht leer sein"})),
        );
    }
    let (id, new_user, phrase) = {
        let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        let id = format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"));
        let (mut user, phrase) = create_user_with_phrase(req.name.trim());
        user.id = id.clone();
        users.push(user.clone());
        save_users(&users);
        (id, user, phrase)
    };

    // ── AccountRegister TX in die Chain schreiben ─────────────────────────
    // Damit ist der Account manipulationssicher in der Blockchain verankert.
    if !new_user.wallet_address.is_empty() {
        let wallet = new_user.wallet_address.clone();
        let name = new_user.name.clone();
        let api_key_hash = new_user.api_key.clone();
        let node = state.node.clone();

        // Signing Key aus der Phrase ableiten (gleiche Logik wie wallet)
        if let Ok(mnemonic) = bip39::Mnemonic::parse_in(bip39::Language::English, &phrase) {
            let entropy = mnemonic.to_entropy();
            let key_bytes: [u8; 32] = if entropy.len() == 32 {
                entropy.try_into().unwrap()
            } else {
                use sha2::{Digest, Sha256};
                let hash: [u8; 32] = Sha256::digest(&entropy).into();
                hash
            };
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

            let nonce = {
                let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                let base = ledger.nonce(&wallet);
                base + node.mempool.sender_pending_count(&wallet)
            };

            let memo = serde_json::json!({
                "name": name,
                "api_key_hash": api_key_hash,
            }).to_string();

            if let Ok(tx) = stone::token::create_signed_tx(
                &signing_key,
                stone::token::TxType::AccountRegister,
                wallet.clone(),
                wallet.clone(),
                rust_decimal::Decimal::ZERO,
                rust_decimal::Decimal::ZERO,
                nonce,
                memo,
                stone::token::transaction::FeeTier::Priority,
            ) {
                // Direkt in den nächsten Block aufnehmen (via Mempool)
                if let Err(e) = node.mempool.add_tx(tx.clone(), None) {
                    eprintln!("[auth] AccountRegister TX → Mempool fehlgeschlagen: {e}");
                } else {
                    println!("[auth] 📝 AccountRegister TX für '{}' erstellt: {}",
                        name, &tx.tx_id[..12]);
                }
            }
        }
    }

    let peers = state.node.get_peers();
    let api_key = state.api_key.clone();
    let push_user = new_user.clone();
    tokio::spawn(async move {
        push_user_to_peers(&push_user, &peers, &api_key).await;
    });

    (
        StatusCode::CREATED,
        axum::Json(json!({
            "id": id,
            "name": new_user.name,
            "api_key": new_user.api_key,
            "wallet_address": new_user.wallet_address,
            "phrase": phrase,
            "message": "Bitte die Phrase sicher aufbewahren – sie wird nur einmal angezeigt.",
        })),
    )
}

/// POST /api/v1/admin/sync-users  (Admin-Key erforderlich)
pub async fn handle_sync_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(incoming): axum::Json<Vec<User>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&headers, &state) {
        return e;
    }
    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;
    let mut updated = 0usize;
    for inc in &incoming {
        if let Some(existing) = users.iter_mut().find(|u| u.id == inc.id) {
            if existing.api_key != inc.api_key || existing.name != inc.name {
                *existing = inc.clone();
                updated += 1;
            }
        } else {
            users.push(inc.clone());
            added += 1;
        }
    }
    if added > 0 || updated > 0 {
        save_users(&users);
    }
    (
        StatusCode::OK,
        axum::Json(json!({ "ok": true, "added": added, "updated": updated })),
    )
    .into_response()
}

/// Pusht einen einzelnen Nutzer an alle bekannten HTTP-Peers via Sync-Port.
pub async fn push_user_to_peers(user: &User, peers: &[PeerInfo], _api_key: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let sync_user = serde_json::json!([{
        "id": user.id,
        "name": user.name,
        "wallet_address": user.wallet_address,
    }]);

    for peer in peers {
        let sync_url = crate::server::sync::to_sync_url(&peer.url);
        let url = format!("{}/sync-users", sync_url);
        match client
            .post(&url)
            .json(&sync_user)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                println!("[auth] Nutzer '{}' an Peer {} gepusht (sync-port)", user.name, peer.url);
            }
            Ok(r) => {
                eprintln!("[auth] Peer {} sync-users: HTTP {}", peer.url, r.status());
            }
            Err(e) => {
                eprintln!("[auth] Peer {} nicht erreichbar: {e}", peer.url);
            }
        }
    }
}

/// POST /api/v1/auth/login
pub async fn handle_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<LoginPhraseRequest>,
) -> impl IntoResponse {
    // Rate Limiting: per IP
    let ip = extract_client_ip(&headers);
    if let Some(resp) = check_rate_limit_tuple(&state.rate_limits.auth_login, &ip, "Login") {
        return resp;
    }

    let Some(hash) = resolve_phrase(&req.phrase) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültige Wiederherstellungs-Phrase"})),
        );
    };
    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(idx) = users.iter().position(|u| u.phrase_hash == hash) {
        // Wallet-Adresse: entweder gespeichert oder live aus der Phrase ableiten
        let mut needs_save = false;
        let wallet_addr = if users[idx].wallet_address.is_empty() {
            // Alt-Account ohne Wallet → jetzt ableiten und PERSISTIEREN
            let addr = stone::auth::wallet_address_from_phrase(&req.phrase);
            if !addr.is_empty() {
                println!("[auth] 💰 Wallet nachträglich aktiviert für {}: {}", users[idx].name, &addr[..16]);
                users[idx].wallet_address = addr.clone();
                needs_save = true;
            }
            addr
        } else {
            users[idx].wallet_address.clone()
        };
        let resp = json!({
            "id": users[idx].id,
            "name": users[idx].name,
            "api_key": users[idx].api_key,
            "wallet_address": wallet_addr,
        });
        if needs_save {
            save_users(&users);
        }

        // ── Auto-Register on-chain falls noch nicht registriert ───────────
        // Benutzer hat sich eingeloggt → wir haben seine Phrase → können die
        // AccountRegister TX erstellen falls noch nicht on-chain.
        if !wallet_addr.is_empty() {
            let is_registered = {
                let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                ledger.all_registered_accounts().contains_key(&wallet_addr)
            };
            if !is_registered {
                let user_name = users[idx].name.clone();
                let api_key_hash = users[idx].api_key.clone();
                let node = state.node.clone();
                let phrase = req.phrase.clone();
                let w = wallet_addr.clone();
                tokio::spawn(async move {
                    if let Ok(mnemonic) = bip39::Mnemonic::parse_in(bip39::Language::English, &phrase) {
                        let entropy = mnemonic.to_entropy();
                        let key_bytes: [u8; 32] = if entropy.len() == 32 {
                            entropy.try_into().unwrap()
                        } else {
                            use sha2::{Digest, Sha256};
                            let hash: [u8; 32] = Sha256::digest(&entropy).into();
                            hash
                        };
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                        let nonce = {
                            let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                            let base = ledger.nonce(&w);
                            base + node.mempool.sender_pending_count(&w)
                        };
                        let memo = serde_json::json!({
                            "name": user_name,
                            "api_key_hash": api_key_hash,
                        }).to_string();
                        if let Ok(tx) = stone::token::create_signed_tx(
                            &signing_key,
                            stone::token::TxType::AccountRegister,
                            w.clone(),
                            w.clone(),
                            rust_decimal::Decimal::ZERO,
                            rust_decimal::Decimal::ZERO,
                            nonce,
                            memo,
                            stone::token::transaction::FeeTier::Priority,
                        ) {
                            if let Err(e) = node.mempool.add_tx(tx.clone(), None) {
                                eprintln!("[auth] Auto-Register TX fehlgeschlagen für {user_name}: {e}");
                            } else {
                                println!("[auth] 📝 Auto-Register TX für '{}' (Login): {}",
                                    user_name, &tx.tx_id[..12]);
                            }
                        }
                    }
                });
            }
        }

        return (StatusCode::OK, axum::Json(resp));
    }

    // ── Fallback: Wallet aus Phrase ableiten (bestehende Wallet ohne lokalen User) ──
    let wallet_addr = stone::auth::wallet_address_from_phrase(&req.phrase);
    if !wallet_addr.is_empty() {
        // Prüfe ob die Wallet on-chain existiert (Balance > 0 oder AccountRegister TX)
        let (is_on_chain, chain_name) = {
            let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
            let registered = ledger.all_registered_accounts();
            if let Some(name) = registered.get(&wallet_addr) {
                (true, name.clone())
            } else if ledger.balance(&wallet_addr) > rust_decimal::Decimal::ZERO {
                (true, String::new())
            } else {
                (false, String::new())
            }
        };

        let display_name = if !chain_name.is_empty() {
            chain_name
        } else {
            format!("Wallet-{}", &wallet_addr[..8])
        };

        // User-Eintrag erstellen und speichern
        let new_id = format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"));
        let new_user = stone::auth::User {
            id: new_id.clone(),
            name: display_name.clone(),
            api_key: hash.clone(),
            phrase_hash: hash,
            quota_bytes: stone::auth::default_quota_bytes(),
            wallet_address: wallet_addr.clone(),
            account_type: stone::auth::default_account_type(),
            org_id: String::new(),
            org_role: String::new(),
        };
        users.push(new_user);
        save_users(&users);

        let resp = json!({
            "id": new_id,
            "name": display_name,
            "api_key": users.last().map(|u| &u.api_key).unwrap(),
            "wallet_address": wallet_addr,
        });

        println!("[auth] 🔗 Bestehende Wallet verknüpft: {} (on-chain: {})", &wallet_addr[..16], is_on_chain);

        // Auto-Register on-chain falls nötig
        if !is_on_chain {
            let user_name = display_name;
            let api_key_hash = users.last().map(|u| u.api_key.clone()).unwrap_or_default();
            let node = state.node.clone();
            let phrase = req.phrase.clone();
            let w = wallet_addr.clone();
            tokio::spawn(async move {
                if let Ok(mnemonic) = bip39::Mnemonic::parse_in(bip39::Language::English, &phrase) {
                    let entropy = mnemonic.to_entropy();
                    let key_bytes: [u8; 32] = if entropy.len() == 32 {
                        entropy.try_into().unwrap()
                    } else {
                        use sha2::{Digest, Sha256};
                        let hash: [u8; 32] = Sha256::digest(&entropy).into();
                        hash
                    };
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                    let nonce = {
                        let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
                        let base = ledger.nonce(&w);
                        base + node.mempool.sender_pending_count(&w)
                    };
                    let memo = serde_json::json!({
                        "name": user_name,
                        "api_key_hash": api_key_hash,
                    }).to_string();
                    if let Ok(tx) = stone::token::create_signed_tx(
                        &signing_key,
                        stone::token::TxType::AccountRegister,
                        w.clone(),
                        w.clone(),
                        rust_decimal::Decimal::ZERO,
                        rust_decimal::Decimal::ZERO,
                        nonce,
                        memo,
                        stone::token::transaction::FeeTier::Priority,
                    ) {
                        let _ = node.mempool.add_tx(tx, None);
                    }
                }
            });
        }

        return (StatusCode::OK, axum::Json(resp));
    }

    drop(users);
    (
        StatusCode::NOT_FOUND,
        axum::Json(
            json!({"error": "Ungültige Phrase"}),
        ),
    )
}

/// POST /api/v1/auth/wallet-claim
///
/// Erlaubt Alt-Accounts (ohne Wallet) einmalig eine Wallet-Adresse zu generieren.
/// Benötigt die Recovery-Phrase zur Authentifizierung + Wallet-Ableitung.
///
/// Body: `{ "phrase": "wort1 wort2 … wort12" }`
/// Antwort: `{ "ok": true, "wallet_address": "…" }` (oder Fehler)
pub async fn handle_wallet_claim(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<LoginPhraseRequest>,
) -> impl IntoResponse {
    let Some(hash) = resolve_phrase(&req.phrase) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültige Wiederherstellungs-Phrase"})),
        );
    };

    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let Some(idx) = users.iter().position(|u| u.phrase_hash == hash) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Phrase nicht bekannt – bitte zuerst registrieren"})),
        );
    };

    // Bereits eine Wallet?
    if !users[idx].wallet_address.is_empty() {
        let addr = users[idx].wallet_address.clone();
        return (
            StatusCode::OK,
            axum::Json(json!({
                "ok": true,
                "wallet_address": addr,
                "message": "Wallet bereits vorhanden",
                "already_claimed": true,
            })),
        );
    }

    // Wallet aus Phrase ableiten
    let addr = stone::auth::wallet_address_from_phrase(&req.phrase);
    if addr.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "Wallet-Ableitung fehlgeschlagen"})),
        );
    }

    users[idx].wallet_address = addr.clone();
    let user_clone = users[idx].clone();
    save_users(&users);
    println!("[auth] 💰 Wallet claimed für {}: {}", user_clone.name, &addr[..16]);

    // An Peers syncen
    let peers = state.node.get_peers();
    let api_key = state.api_key.clone();
    drop(users);

    tokio::spawn(async move {
        push_user_to_peers(&user_clone, &peers, &api_key).await;
    });

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "wallet_address": addr,
            "message": "Wallet erfolgreich aktiviert!",
            "already_claimed": false,
        })),
    )
}

// ─── Challenge-Response Auth (Cross-Platform Login) ──────────────────────────

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub wallet_address: String,
}

#[derive(Deserialize)]
pub struct VerifyChallengeRequest {
    pub wallet_address: String,
    pub signature: String,
}

/// POST /api/v1/auth/challenge
///
/// Erzeugt einen Challenge-Nonce für Wallet-basierte Authentifizierung.
/// Der Client signiert den Nonce mit seinem privaten Schlüssel (aus der Seed-Phrase).
///
/// Body: `{ "wallet_address": "hex_ed25519_pubkey" }`
/// Antwort: `{ "challenge": "hex_nonce", "expires_in": 300 }`
pub async fn handle_request_challenge(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<ChallengeRequest>,
) -> impl IntoResponse {
    let wallet = req.wallet_address.trim();

    if wallet.is_empty() || wallet.len() != 64 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültige Wallet-Adresse (64 Hex-Zeichen erwartet)"})),
        );
    }

    // Prüfe ob ein User mit dieser Wallet existiert
    {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        if !users.iter().any(|u| u.wallet_address == wallet) {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Keine Registrierung für diese Wallet-Adresse gefunden"})),
            );
        }
    }

    let challenge = state.challenge_store.create_challenge(wallet);
    (
        StatusCode::OK,
        axum::Json(json!({
            "challenge": challenge.nonce,
            "expires_in": stone::auth::CHALLENGE_TTL_SECS,
        })),
    )
}

/// POST /api/v1/auth/verify
///
/// Verifiziert die signierte Challenge und gibt einen Session-Token zurück.
/// Der Client signiert den Challenge-Nonce mit dem Ed25519 Private Key,
/// der aus der Seed-Phrase abgeleitet wird.
///
/// Body: `{ "wallet_address": "hex_pubkey", "signature": "hex_ed25519_sig" }`
/// Antwort: `{ "session_token": "…", "user": { … }, "expires_in": 86400 }`
pub async fn handle_verify_challenge(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<VerifyChallengeRequest>,
) -> impl IntoResponse {
    let wallet = req.wallet_address.trim().to_string();
    let signature = req.signature.trim().to_string();

    if wallet.is_empty() || wallet.len() != 64 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültige Wallet-Adresse"})),
        );
    }

    // Challenge konsumieren (einmalig verwendbar)
    let challenge = match state.challenge_store.consume_challenge(&wallet) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "Kein gültiger Challenge vorhanden – bitte zuerst /auth/challenge aufrufen"})),
            );
        }
    };

    // Ed25519-Signatur des Nonce verifizieren
    if !verify_challenge_signature(&wallet, &challenge.nonce, &signature) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "Signaturprüfung fehlgeschlagen – falscher Private Key?"})),
        );
    }

    // User anhand der Wallet-Adresse finden
    let user = {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        users.iter().find(|u| u.wallet_address == wallet).cloned()
    };

    let Some(user) = user else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "User nicht gefunden"})),
        );
    };

    // Session-Token erzeugen (HMAC-signiert, 24h gültig)
    let token = generate_session_token(
        &user.id,
        &wallet,
        &state.api_key,
        SESSION_TOKEN_TTL_SECS,
    );

    println!(
        "[auth] 🔑 Challenge-Response Login erfolgreich: {} ({})",
        user.name,
        &wallet[..16]
    );

    (
        StatusCode::OK,
        axum::Json(json!({
            "session_token": token,
            "expires_in": SESSION_TOKEN_TTL_SECS,
            "user": {
                "id": user.id,
                "name": user.name,
                "wallet_address": user.wallet_address,
                "account_type": user.account_type,
            },
        })),
    )
}

// ─── QR-Code Login (Cross-Device Authentifizierung) ──────────────────────────

#[derive(Deserialize)]
pub struct QrApproveRequest {
    pub login_token: String,
    /// Optionale Mnemonic-Phrase für Chat-Signierung im QR-Login
    pub phrase: Option<String>,
}

/// POST /api/v1/auth/qr/create
///
/// Erzeugt eine neue QR-Login-Session. Die Website zeigt den `login_token` als QR-Code.
/// Kein Auth erforderlich (die Website ist noch nicht eingeloggt).
///
/// Antwort: `{ "login_token": "hex", "expires_in": 180 }`
pub async fn handle_qr_create(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let session = state.qr_login_store.create_session();

    println!(
        "[auth] 📱 QR-Login-Session erstellt: {}…",
        &session.login_token[..16]
    );

    (
        StatusCode::OK,
        axum::Json(json!({
            "login_token": session.login_token,
            "expires_in": QR_LOGIN_TTL_SECS,
        })),
    )
}

/// GET /api/v1/auth/qr/status/:token
///
/// Pollt den Status einer QR-Login-Session.
/// Die Website ruft diesen Endpoint wiederholt auf, bis `status == "approved"`.
///
/// Antwort (pending): `{ "status": "pending" }`
/// Antwort (approved): `{ "status": "approved", "session_token": "…", "user": {…}, "api_key": "…" }`
/// Antwort (expired): `{ "status": "expired" }`
pub async fn handle_qr_status(
    State(state): State<AppState>,
    Path(login_token): Path<String>,
) -> impl IntoResponse {
    let Some(session) = state.qr_login_store.get_status(&login_token) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"status": "expired", "error": "QR-Session nicht gefunden oder abgelaufen"})),
        );
    };

    match session.status {
        stone::auth::QrLoginStatus::Pending => {
            (
                StatusCode::OK,
                axum::Json(json!({"status": "pending"})),
            )
        }
        stone::auth::QrLoginStatus::Approved => {
            // Session konsumieren (einmalig abrufbar)
            if let Some(approved) = state.qr_login_store.consume_approved(&login_token) {
                // api_key des Users für Legacy-Kompatibilität mitgeben
                let api_key = {
                    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
                    approved.approved_wallet.as_ref()
                        .and_then(|w| users.iter().find(|u| &u.wallet_address == w))
                        .map(|u| u.api_key.clone())
                        .unwrap_or_default()
                };

                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "status": "approved",
                        "session_token": approved.session_token,
                        "expires_in": SESSION_TOKEN_TTL_SECS,
                        "api_key": api_key,                        "phrase": approved.approved_phrase,                        "user": {
                            "id": approved.approved_user_id,
                            "name": approved.approved_user_name,
                            "wallet_address": approved.approved_wallet,
                            "account_type": approved.approved_account_type,
                        },
                    })),
                )
            } else {
                (
                    StatusCode::GONE,
                    axum::Json(json!({"status": "expired", "error": "QR-Session bereits abgerufen"})),
                )
            }
        }
        stone::auth::QrLoginStatus::Expired => {
            (
                StatusCode::GONE,
                axum::Json(json!({"status": "expired"})),
            )
        }
    }
}

/// POST /api/v1/auth/qr/approve
///
/// Die iOS App genehmigt eine QR-Login-Session.
/// Erfordert einen gültigen Bearer-Token (der User muss in der App eingeloggt sein).
/// Nach FaceID-Bestätigung sendet die App diesen Request.
///
/// Body: `{ "login_token": "hex" }`
/// Antwort: `{ "ok": true }`
pub async fn handle_qr_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<QrApproveRequest>,
) -> impl IntoResponse {
    // Der User muss authentifiziert sein (Bearer Token aus der App)
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let login_token = req.login_token.trim();
    if login_token.is_empty() || login_token.len() != 64 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültiger login_token (64 Hex-Zeichen erwartet)"})),
        )
            .into_response();
    }

    // Neuen Session-Token für das Website-Login generieren
    let session_token = generate_session_token(
        &user.id,
        &user.wallet_address,
        &state.api_key,
        SESSION_TOKEN_TTL_SECS,
    );

    if state.qr_login_store.approve_session(login_token, session_token, &user, req.phrase.clone()) {
        println!(
            "[auth] 📱✅ QR-Login genehmigt von {} ({}) für Token {}…",
            user.name,
            &user.wallet_address.get(..16).unwrap_or(&user.wallet_address),
            &login_token[..16]
        );

        (
            StatusCode::OK,
            axum::Json(json!({
                "ok": true,
                "message": "QR-Login erfolgreich genehmigt",
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "ok": false,
                "error": "QR-Session ungültig, abgelaufen oder bereits genehmigt",
            })),
        )
            .into_response()
    }
}
