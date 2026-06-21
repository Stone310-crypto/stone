//! Auth handlers: signup, login, sync-users, push_user_to_peers, challenge-response, QR-login.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
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
    master::PeerInfo,
};

use super::super::auth_middleware::{require_admin, require_user};
use super::super::rate_limiter::{check_rate_limit_tuple, extract_client_ip};
use super::super::state::AppState;

// ── Nomad-Forwarding ────────────────────────────────────────────────────

pub fn forward_to_nomad(path: &str, body: serde_json::Value) {
    let nomad_url = match std::env::var("NOMAD_URL") {
        Ok(u) if !u.is_empty() => u.trim_end_matches('/').to_string(),
        _ => return,
    };
    let node_secret = std::env::var("NODE_SECRET").unwrap_or_default();
    let url = format!("{}{}", nomad_url, path);
    let path_owned = path.to_string();

    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        match client.post(&url).header("X-Node-Secret", &node_secret).header("Content-Type", "application/json").json(&body).send().await {
            Ok(resp) => {
                if resp.status().is_success() { println!("[nomad] ✓ Forwarded to {}", path_owned); }
                else { eprintln!("[nomad] ✗ {} → HTTP {}", path_owned, resp.status()); }
            }
            Err(e) => eprintln!("[nomad] ✗ {} → {}", path_owned, e),
        }
    });
}

#[derive(Deserialize)] pub struct SignupRequest { pub name: String }
#[derive(Deserialize)] pub struct LoginPhraseRequest { pub phrase: String }

/// POST /api/v1/auth/signup
pub async fn handle_signup(State(state): State<AppState>, headers: HeaderMap, axum::Json(req): axum::Json<SignupRequest>) -> impl IntoResponse {
    let ip = extract_client_ip(&headers);
    if let Some(resp) = check_rate_limit_tuple(&state.rate_limits.auth_signup, &ip, "Signup") { return resp; }
    if req.name.trim().is_empty() { return (StatusCode::BAD_REQUEST, axum::Json(json!({"error":"Name darf nicht leer sein"}))); }
    let (id, new_user, phrase) = {
        let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        let id = format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"));
        let (mut user, phrase) = create_user_with_phrase(req.name.trim());
        user.id = id.clone();
        users.push(user.clone());
        save_users(&users);
        (id, user, phrase)
    };

    if !new_user.wallet_address.is_empty() {
        let wallet = new_user.wallet_address.clone();
        let name = new_user.name.clone();
        let api_key_hash = new_user.api_key.clone();
        let node = state.node.clone();
        if let Ok(mnemonic) = bip39::Mnemonic::parse_in(bip39::Language::English, &phrase) {
            let entropy = mnemonic.to_entropy();
            let key_bytes: [u8;32] = if entropy.len()==32 { entropy.try_into().unwrap() } else { use sha2::{Digest,Sha256}; Sha256::digest(&entropy).into() };
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            let nonce = { let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner()); ledger.nonce(&wallet) + node.mempool.sender_pending_count(&wallet) };
            let memo = serde_json::json!({"name":name,"api_key_hash":api_key_hash}).to_string();
            if let Ok(tx) = stone::token::create_signed_tx(&signing_key, stone::token::TxType::AccountRegister, wallet.clone(), wallet.clone(), rust_decimal::Decimal::ZERO, rust_decimal::Decimal::ZERO, nonce, memo, stone::token::transaction::FeeTier::Priority) {
                if let Err(e) = node.mempool.add_tx(tx.clone(), None) { eprintln!("[auth] Mempool: {e}"); }
                else { println!("[auth] 📝 AccountRegister TX für '{}': {}", name, &tx.tx_id[..12]); }
            }
        }
    }

    let peers = state.node.get_peers();
    let api_key = state.api_key.clone();
    let push_user = new_user.clone();
    tokio::spawn(async move { push_user_to_peers(&push_user, &peers, &api_key).await; });
    let node_url = std::env::var("PUBLIC_URL").unwrap_or_default();
    forward_to_nomad("/stone/testnet/register", json!({"user_id":id,"name":new_user.name,"wallet_address":new_user.wallet_address,"node_url":node_url}));
    (StatusCode::CREATED, axum::Json(json!({"id":id,"name":new_user.name,"api_key":new_user.api_key,"wallet_address":new_user.wallet_address,"phrase":phrase,"message":"Bitte die Phrase sicher aufbewahren – sie wird nur einmal angezeigt."})))
}

/// POST /api/v1/admin/sync-users (Admin-Key erforderlich)
pub async fn handle_sync_users(State(state): State<AppState>, headers: HeaderMap, axum::Json(incoming): axum::Json<Vec<User>>) -> impl IntoResponse {
    if let Err(e) = require_admin(&headers, &state) { return e; }
    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let mut added=0; let mut updated=0;
    for inc in &incoming {
        if let Some(existing) = users.iter_mut().find(|u| u.id == inc.id) {
            if existing.api_key != inc.api_key || existing.name != inc.name { *existing = inc.clone(); updated+=1; }
        } else { users.push(inc.clone()); added+=1; }
    }
    if added>0||updated>0 { save_users(&users); }
    (StatusCode::OK, axum::Json(json!({"ok":true,"added":added,"updated":updated}))).into_response()
}

pub async fn push_user_to_peers(user: &User, peers: &[PeerInfo], api_key: &str) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v|v=="1").unwrap_or(false)).build() { Ok(c)=>c, Err(_)=>return };
    for peer in peers {
        let sync_url = crate::server::sync::to_sync_url(&peer.url);
        let _ = client.post(&format!("{}/sync-users",sync_url)).header("x-api-key",api_key).json(&serde_json::json!([{"id":user.id,"name":user.name,"api_key":user.api_key,"wallet_address":user.wallet_address}])).send().await;
    }
}

/// POST /api/v1/auth/login
pub async fn handle_login(State(state): State<AppState>, headers: HeaderMap, axum::Json(req): axum::Json<LoginPhraseRequest>) -> impl IntoResponse {
    let ip = extract_client_ip(&headers);
    if let Some(resp) = check_rate_limit_tuple(&state.rate_limits.auth_login, &ip, "Login") { return resp; }
    let Some(hash) = resolve_phrase(&req.phrase) else { return (StatusCode::BAD_REQUEST, axum::Json(json!({"error":"Ungültige Wiederherstellungs-Phrase"}))); };
    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(idx) = users.iter().position(|u| u.phrase_hash == hash) {
        let wallet_addr = if users[idx].wallet_address.is_empty() {
            let addr = stone::auth::wallet_address_from_phrase(&req.phrase);
            if !addr.is_empty() { users[idx].wallet_address = addr.clone(); }
            addr
        } else { users[idx].wallet_address.clone() };
        let session_token = generate_session_token(&users[idx].id, &wallet_addr, &state.api_key, SESSION_TOKEN_TTL_SECS);
        if users[idx].wallet_address.is_empty() && !stone::auth::wallet_address_from_phrase(&req.phrase).is_empty() { users[idx].wallet_address = stone::auth::wallet_address_from_phrase(&req.phrase); save_users(&users); }
        return (StatusCode::OK, axum::Json(json!({"id":users[idx].id,"name":users[idx].name,"api_key":users[idx].api_key,"wallet_address":wallet_addr,"session_token":session_token})));
    }
    (StatusCode::NOT_FOUND, axum::Json(json!({"error":"Ungültige Phrase"})))
}

/// POST /api/v1/auth/wallet-claim — Alt-Account Wallet aktivieren
pub async fn handle_wallet_claim(State(state): State<AppState>, axum::Json(req): axum::Json<LoginPhraseRequest>) -> impl IntoResponse {
    let Some(hash) = resolve_phrase(&req.phrase) else { return (StatusCode::BAD_REQUEST, axum::Json(json!({"error":"Ungültige Phrase"}))); };
    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let Some(idx) = users.iter().position(|u| u.phrase_hash == hash) else { return (StatusCode::NOT_FOUND, axum::Json(json!({"error":"Phrase nicht bekannt"}))); };
    if !users[idx].wallet_address.is_empty() { return (StatusCode::OK, axum::Json(json!({"ok":true,"wallet_address":users[idx].wallet_address,"already_claimed":true}))); }
    let addr = stone::auth::wallet_address_from_phrase(&req.phrase);
    if addr.is_empty() { return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error":"Wallet-Ableitung fehlgeschlagen"}))); }
    users[idx].wallet_address = addr.clone();
    let user_clone = users[idx].clone();
    save_users(&users);
    let peers = state.node.get_peers(); let api_key = state.api_key.clone();
    drop(users);
    tokio::spawn(async move { push_user_to_peers(&user_clone, &peers, &api_key).await; });
    (StatusCode::OK, axum::Json(json!({"ok":true,"wallet_address":addr})))
}

// ─── QR-Code Login ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct QrApproveRequest {
    pub login_token: String,
    pub phrase: Option<String>,
    pub wallet_address: Option<String>,
    pub wallet_signature: Option<String>,
}

async fn forward_qr_approve_to_peers(state: &AppState, login_token: &str, _session_token: &str, user: &User, phrase: Option<String>) -> bool {
    let peers = state.node.get_peers();
    if peers.is_empty() { return false; }
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(5)).danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v|v=="1").unwrap_or(false)).build() { Ok(c)=>c, Err(_)=>return false };
    let body = serde_json::json!({"login_token":login_token,"phrase":phrase,"wallet_address":user.wallet_address});
    for peer in &peers {
        let api_url = format!("{}/api/v1/auth/qr/approve", peer.url.trim_end_matches('/'));
        let sync_url = crate::server::sync::to_sync_url(&peer.url);
        let sync_qr_url = format!("{}/qr-approve", sync_url);
        for url in &[&api_url, &sync_qr_url] {
            match client.post(*url).json(&body).timeout(Duration::from_secs(3)).send().await {
                Ok(r) if r.status().is_success() => { println!("[auth] 📱 QR-Forward ok via {}", url); return true; }
                _ => {}
            }
        }
    }
    false
}

/// POST /api/v1/auth/qr/create — Erstellt QR-Session lokal + pushed an Peers
pub async fn handle_qr_create(State(state): State<AppState>) -> impl IntoResponse {
    let session = state.qr_login_store.create_session();
    let token = session.login_token.clone();
    println!("[auth] 📱 QR-Session erstellt: {}…", &token[..16]);

    // Sofort an alle Peers pushen (Sync-Port), damit VPS die Session kennt
    let peers = state.node.get_peers();
    if !peers.is_empty() {
        let token_clone = token.clone();
        let peers_clone = peers.clone();
        let body = serde_json::json!({"login_token":token_clone});
        tokio::spawn(async move {
            let client = match reqwest::Client::builder().timeout(Duration::from_secs(5)).danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v|v=="1").unwrap_or(false)).build() { Ok(c)=>c, Err(_)=>return };
            for peer in &peers_clone {
                // Push session creation to peer's sync port
                let sync_url = crate::server::sync::to_sync_url(&peer.url);
                let url = format!("{}/qr-create", sync_url);
                match client.post(&url).json(&body).timeout(Duration::from_secs(3)).send().await {
                    Ok(r) if r.status().is_success() => {
                        println!("[auth] 📱 QR-Session an Peer {} gepusht", peer.url);
                    }
                    _ => {}
                }
            }
        });
    }

    (StatusCode::OK, axum::Json(json!({"login_token":token,"expires_in":QR_LOGIN_TTL_SECS})))
}

/// GET /api/v1/auth/qr/status/:token — Pollt QR-Session (lokal + Peers)
pub async fn handle_qr_status(State(state): State<AppState>, Path(login_token): Path<String>) -> impl IntoResponse {
    if let Some(session) = state.qr_login_store.get_status(&login_token) {
        return match session.status {
            stone::auth::QrLoginStatus::Pending => (StatusCode::OK, axum::Json(json!({"status":"pending"}))).into_response(),
            stone::auth::QrLoginStatus::Approved => {
                if let Some(approved) = state.qr_login_store.consume_approved(&login_token) {
                    let api_key = { let users = state.users.lock().unwrap_or_else(|e| e.into_inner()); approved.approved_wallet.as_ref().and_then(|w|users.iter().find(|u|&u.wallet_address==w)).map(|u|u.api_key.clone()).unwrap_or_default() };
                    return (StatusCode::OK, axum::Json(json!({"status":"approved","session_token":approved.session_token,"expires_in":SESSION_TOKEN_TTL_SECS,"api_key":api_key,"phrase":approved.approved_phrase,"user":{"id":approved.approved_user_id,"name":approved.approved_user_name,"wallet_address":approved.approved_wallet,"account_type":approved.approved_account_type,"discord_id":approved.approved_discord_id,"discord_username":approved.approved_discord_username}}))).into_response();
                }
                (StatusCode::GONE, axum::Json(json!({"status":"expired"}))).into_response()
            }
            stone::auth::QrLoginStatus::Expired => (StatusCode::GONE, axum::Json(json!({"status":"expired"}))).into_response(),
        };
    }
    // Poll peers
    if let Some(approved) = poll_peers_for_qr_session(&state, &login_token).await {
        let user = stone::auth::User { id: approved.user_id.clone(), name: approved.user_name.clone(), api_key: String::new(), phrase_hash: String::new(), quota_bytes: stone::auth::default_quota_bytes(), wallet_address: approved.wallet_address.clone(), account_type: approved.account_type.clone(), org_id: String::new(), org_role: String::new(), discord_id: approved.discord_id.clone(), discord_username: approved.discord_username.clone() };
        let session_token = generate_session_token(&user.id, &user.wallet_address, &state.api_key, SESSION_TOKEN_TTL_SECS);
        let _ = state.qr_login_store.approve_session(&login_token, session_token.clone(), &user, approved.phrase.clone());
        let api_key = { let users = state.users.lock().unwrap_or_else(|e| e.into_inner()); users.iter().find(|u|u.wallet_address==user.wallet_address).map(|u|u.api_key.clone()).unwrap_or_default() };
        return (StatusCode::OK, axum::Json(json!({"status":"approved","session_token":session_token,"api_key":api_key,"phrase":approved.phrase,"user":{"id":user.id,"name":user.name,"wallet_address":user.wallet_address,"account_type":user.account_type,"discord_id":user.discord_id,"discord_username":user.discord_username}}))).into_response();
    }
    (StatusCode::NOT_FOUND, axum::Json(json!({"status":"expired","error":"QR-Session nicht gefunden oder abgelaufen"}))).into_response()
}

#[derive(serde::Deserialize)]
struct QrSessionApproved {
    user_id: String, user_name: String, wallet_address: String, account_type: String,
    #[serde(default)] discord_id: String,
    #[serde(default)] discord_username: String,
    #[serde(default)] phrase: Option<String>,
}

async fn poll_peers_for_qr_session(state: &AppState, login_token: &str) -> Option<QrSessionApproved> {
    let peers = state.node.get_peers();
    if peers.is_empty() { return None; }
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(3)).danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v|v=="1").unwrap_or(false)).build() { Ok(c)=>c, Err(_)=>return None };
    for peer in &peers {
        let sync_url = crate::server::sync::to_sync_url(&peer.url);
        match client.get(&format!("{}/qr-status/{}",sync_url,login_token)).timeout(Duration::from_secs(3)).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    if body.get("status").and_then(|v|v.as_str()) == Some("approved") {
                        return serde_json::from_value::<QrSessionApproved>(body).ok();
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// POST /api/v1/auth/qr/approve
pub async fn handle_qr_approve(State(state): State<AppState>, headers: HeaderMap, axum::Json(req): axum::Json<QrApproveRequest>) -> impl IntoResponse {
    let login_token = req.login_token.trim().to_string();
    if login_token.is_empty() || login_token.len()!=64 { return (StatusCode::BAD_REQUEST, axum::Json(json!({"error":"Ungültiger login_token"}))).into_response(); }

    if let (Some(ref wallet), Some(ref sig)) = (req.wallet_address.as_deref(), req.wallet_signature.as_deref()) {
        let wallet = wallet.trim(); let sig = sig.trim();
        if !wallet.is_empty() && wallet.len()==64 && !sig.is_empty() && sig.len()==128 {
            if verify_challenge_signature(wallet, &login_token, sig) {
                let user = { let users = state.users.lock().unwrap_or_else(|e| e.into_inner()); users.iter().find(|u|u.wallet_address==wallet).cloned().unwrap_or(stone::auth::User { id: format!("u-{}",&wallet[..8]), name: format!("Wallet-{}",&wallet[..12]), api_key: String::new(), phrase_hash: String::new(), quota_bytes: stone::auth::default_quota_bytes(), wallet_address: wallet.to_string(), account_type: stone::auth::default_account_type(), org_id: String::new(), org_role: String::new(), discord_id: String::new(), discord_username: String::new() }) };
                let session_token = generate_session_token(&user.id, &user.wallet_address, &state.api_key, SESSION_TOKEN_TTL_SECS);
                if state.qr_login_store.approve_session(&login_token, session_token.clone(), &user, req.phrase.clone()) {
                    println!("[auth] 📱✅ QR-Login genehmigt: {}", user.name);
                    return (StatusCode::OK, axum::Json(json!({"ok":true}))).into_response();
                }
                if forward_qr_approve_to_peers(&state, &login_token, &session_token, &user, req.phrase.clone()).await {
                    return (StatusCode::OK, axum::Json(json!({"ok":true}))).into_response();
                }
                return (StatusCode::BAD_REQUEST, axum::Json(json!({"error":"QR-Session nicht gefunden"}))).into_response();
            }
        }
    }

    let user = match require_user(&headers, &state) { Ok(u)=>u, Err(resp)=>return resp.into_response() };
    let session_token = generate_session_token(&user.id, &user.wallet_address, &state.api_key, SESSION_TOKEN_TTL_SECS);
    if state.qr_login_store.approve_session(&login_token, session_token, &user, req.phrase.clone()) {
        (StatusCode::OK, axum::Json(json!({"ok":true}))).into_response()
    } else {
        (StatusCode::BAD_REQUEST, axum::Json(json!({"error":"QR-Session nicht gefunden"}))).into_response()
    }
}

// ─── Stub-Handler (non-chat methods are in the full file, this is just the QR fix) ──

#[derive(Deserialize)] pub struct ChallengeRequest { pub wallet_address: String }
#[derive(Deserialize)] pub struct VerifyChallengeRequest { pub wallet_address: String, pub signature: String }

pub async fn handle_request_challenge(State(state): State<AppState>, axum::Json(req): axum::Json<ChallengeRequest>) -> impl IntoResponse {
    let wallet = req.wallet_address.trim();
    if wallet.is_empty() || wallet.len()!=64 { return (StatusCode::BAD_REQUEST, axum::Json(json!({"error":"Ungültige Wallet-Adresse"}))); }
    let challenge = state.challenge_store.create_challenge(wallet);
    (StatusCode::OK, axum::Json(json!({"challenge":challenge.nonce,"expires_in":stone::auth::CHALLENGE_TTL_SECS})))
}

pub async fn handle_verify_challenge(State(state): State<AppState>, axum::Json(req): axum::Json<VerifyChallengeRequest>) -> impl IntoResponse {
    let wallet = req.wallet_address.trim().to_string();
    let challenge = match state.challenge_store.consume_challenge(&wallet) { Some(c)=>c, None=>return (StatusCode::UNAUTHORIZED, axum::Json(json!({"error":"Kein gültiger Challenge"}))) };
    if !verify_challenge_signature(&wallet, &challenge.nonce, &req.signature) { return (StatusCode::UNAUTHORIZED, axum::Json(json!({"error":"Signatur falsch"}))); }
    let user = { let users = state.users.lock().unwrap_or_else(|e| e.into_inner()); users.iter().find(|u|u.wallet_address==wallet).cloned() };
    let Some(user) = user else { return (StatusCode::NOT_FOUND, axum::Json(json!({"error":"User nicht gefunden"}))); };
    let token = generate_session_token(&user.id, &wallet, &state.api_key, SESSION_TOKEN_TTL_SECS);
    (StatusCode::OK, axum::Json(json!({"session_token":token,"user":{"id":user.id,"name":user.name,"wallet_address":user.wallet_address}})))
}

#[derive(Deserialize)] pub struct UpdateProfileRequest { pub name: Option<String> }
pub async fn handle_profile_update(State(state): State<AppState>, headers: HeaderMap, axum::Json(req): axum::Json<UpdateProfileRequest>) -> impl IntoResponse {
    let user = match require_user(&headers, &state) { Ok(u)=>u, Err(resp)=>return resp.into_response() };
    let new_name = match req.name { Some(n) if !n.trim().is_empty() => n.trim().to_string(), _=>return (StatusCode::BAD_REQUEST,"Kein Name").into_response() };
    { let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner()); if let Some(u)=users.iter_mut().find(|u|u.api_key==user.api_key||u.wallet_address==user.wallet_address) { u.name=new_name.clone(); save_users(&users); } }
    (StatusCode::OK, axum::Json(json!({"name":new_name}))).into_response()
}

#[derive(Deserialize)] pub struct DiscordLoginRequest { pub code: String, pub redirect_uri: String }
pub async fn handle_discord_login(State(_state): State<AppState>, headers: HeaderMap, axum::Json(_req): axum::Json<DiscordLoginRequest>) -> impl IntoResponse {
    (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({"error":"Discord-Login in app_node nicht verfügbar"})))
}

#[derive(Deserialize)] pub struct DiscordCallbackParams { pub code: Option<String>, pub error: Option<String> }
pub async fn handle_discord_callback(Query(params): Query<DiscordCallbackParams>) -> impl IntoResponse {
    if let Some(err) = params.error { return axum::response::Redirect::temporary(&format!("stonechain://auth/discord?error={err}")).into_response(); }
    let code = match params.code { Some(c) if !c.is_empty()=>c, _=>return axum::response::Redirect::temporary("stonechain://auth/discord?error=missing_code").into_response() };
    axum::response::Redirect::temporary(&format!("stonechain://auth/discord?code={code}")).into_response()
}