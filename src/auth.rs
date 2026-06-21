use base64::Engine as _;
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::blockchain::data_dir;

fn users_file() -> String { format!("{}/users.json", data_dir()) }
pub const USERS_FILE_COMPAT: &str = "stone_data/users.json"; // für externe Tools

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub name: String,
    pub api_key: String,
    pub phrase_hash: String,
    pub quota_bytes: u64,
    #[serde(default)]
    pub wallet_address: String,
    #[serde(default)]
    pub account_type: String,
    #[serde(default)]
    pub org_id: String,
    #[serde(default)]
    pub org_role: String,
    #[serde(default)]
    pub discord_id: String,
    #[serde(default)]
    pub discord_username: String,
}

pub fn default_quota_bytes() -> u64 { 1024 * 1024 * 1024 }
pub fn default_account_type() -> String { "user".into() }

pub fn load_users() -> Arc<Mutex<Vec<User>>> {
    let users = if let Ok(data) = fs::read_to_string(users_file()) {
        serde_json::from_str(&data).unwrap_or_default()
    } else { Vec::new() };
    Arc::new(Mutex::new(users))
}

pub fn save_users(users: &[User]) {
    if let Ok(json) = serde_json::to_string_pretty(users) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(users_file(), json);
    }
    if let Some(db) = crate::database::global_db() { let _ = db.save_users(users); }
}

pub fn create_user_with_phrase(name: &str) -> (User, String) {
    let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();
    let phrase = mnemonic.to_string();
    let mut h = Sha256::new();
    h.update(phrase.as_bytes());
    let hash = hex::encode(h.finalize());
    let api_key = format!("sk_{}", hex::encode(&rand::random::<[u8;16]>()));
    let wallet = wallet_address_from_phrase(&phrase);
    let user = User { id: String::new(), name: name.into(), api_key, phrase_hash: hash, quota_bytes: default_quota_bytes(), wallet_address: wallet, account_type: default_account_type(), org_id: String::new(), org_role: String::new(), discord_id: String::new(), discord_username: String::new() };
    (user, phrase)
}

pub fn resolve_phrase(phrase: &str) -> Option<String> {
    let mut h = Sha256::new();
    h.update(phrase.as_bytes());
    Some(hex::encode(h.finalize()))
}

pub fn wallet_address_from_phrase(phrase: &str) -> String {
    if let Ok(mnemonic) = Mnemonic::parse_in(Language::English, phrase.trim()) {
        let entropy = mnemonic.to_entropy();
        let key: [u8;32] = if entropy.len()==32 { entropy.try_into().unwrap() } else { Sha256::digest(&entropy).into() };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key);
        hex::encode(signing_key.verifying_key().to_bytes())
    } else { String::new() }
}

pub const SESSION_TOKEN_TTL_SECS: i64 = 86400;
pub const CHALLENGE_TTL_SECS: u64 = 300;
pub const QR_LOGIN_TTL_SECS: u64 = 180;

pub fn generate_session_token(user_id: &str, wallet: &str, api_key: &str, ttl: i64) -> String {
    let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64 + ttl;
    let payload = format!("{}|{}|{}|{}", user_id, wallet, api_key, exp);
    let mut mac = Hmac::<Sha256>::new_from_slice(api_key.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    format!("{}.{}", encoded, sig)
}

pub fn verify_challenge_signature(wallet_address: &str, nonce: &str, signature: &str) -> bool {
    if wallet_address.len()!=64 || signature.len()!=128 { return false; }
    let pub_bytes = hex::decode(wallet_address).ok().unwrap_or_default();
    if pub_bytes.len()!=32 { return false; }
    let sig_bytes = hex::decode(signature).ok().unwrap_or_default();
    if sig_bytes.len()!=64 { return false; }
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap()) { Ok(v) => v, Err(_) => return false };
    let sig = match ed25519_dalek::Signature::from_slice(sig_bytes.as_slice()) { Ok(s) => s, Err(_) => return false };
    vk.verify_strict(nonce.as_bytes(), &sig).is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrLoginStatus { Pending, Approved, Expired }

#[derive(Debug, Clone)]
pub struct QrLoginSession {
    pub login_token: String,
    pub status: QrLoginStatus,
    pub created_at: u64,
    pub expires_at: u64,
    pub approved_user_id: Option<String>,
    pub approved_user_name: Option<String>,
    pub approved_wallet: Option<String>,
    pub approved_account_type: Option<String>,
    pub approved_discord_id: Option<String>,
    pub approved_discord_username: Option<String>,
    pub approved_phrase: Option<String>,
    pub session_token: Option<String>,
}

impl QrLoginSession {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        now > self.expires_at
    }
}

#[derive(Clone)]
pub struct QrLoginStore {
    inner: Arc<Mutex<HashMap<String, QrLoginSession>>>,
}

impl QrLoginStore {
    pub fn new() -> Self { Self { inner: Arc::new(Mutex::new(HashMap::new())) } }

    pub fn create_session(&self) -> QrLoginSession {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let token = hex::encode(&rand::random::<[u8;32]>());
        let session = QrLoginSession { login_token: token.clone(), status: QrLoginStatus::Pending, created_at: now, expires_at: now + QR_LOGIN_TTL_SECS, approved_user_id: None, approved_user_name: None, approved_wallet: None, approved_account_type: None, approved_discord_id: None, approved_discord_username: None, approved_phrase: None, session_token: None };
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.insert(token, session.clone());
        session
    }

    /// Externally created pending session (received from a peer).
    pub fn add_pending_session(&self, login_token: &str) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let session = QrLoginSession { login_token: login_token.to_string(), status: QrLoginStatus::Pending, created_at: now, expires_at: now + QR_LOGIN_TTL_SECS, approved_user_id: None, approved_user_name: None, approved_wallet: None, approved_account_type: None, approved_discord_id: None, approved_discord_username: None, approved_phrase: None, session_token: None };
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.insert(login_token.to_string(), session);
        true
    }

    pub fn get_status(&self, login_token: &str) -> Option<QrLoginSession> {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = m.get(login_token) { if s.is_expired() { m.remove(login_token); None } else { Some(s.clone()) } } else { None }
    }

    pub fn approve_session(&self, login_token: &str, session_token: String, user: &User, phrase: Option<String>) -> bool {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = m.get_mut(login_token) {
            s.status = QrLoginStatus::Approved;
            s.session_token = Some(session_token);
            s.approved_user_id = Some(user.id.clone());
            s.approved_user_name = Some(user.name.clone());
            s.approved_wallet = Some(user.wallet_address.clone());
            s.approved_account_type = Some(user.account_type.clone());
            s.approved_discord_id = Some(user.discord_id.clone());
            s.approved_discord_username = Some(user.discord_username.clone());
            s.approved_phrase = phrase;
            true
        } else { false }
    }

    pub fn consume_approved(&self, login_token: &str) -> Option<QrLoginSession> {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.remove(login_token)
    }
}

impl Default for QrLoginStore { fn default() -> Self { Self::new() } }

#[derive(Clone)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, Challenge>>>,
}

#[derive(Debug, Clone)]
pub struct Challenge { pub nonce: String, pub created_at: u64, pub wallet: String }

impl ChallengeStore {
    pub fn new() -> Self { Self { inner: Arc::new(Mutex::new(HashMap::new())) } }
    pub fn create_challenge(&self, wallet: &str) -> Challenge {
        let nonce = hex::encode(&rand::random::<[u8;32]>());
        let c = Challenge { nonce, created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(), wallet: wallet.to_string() };
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.insert(wallet.to_string(), c.clone());
        c
    }
    pub fn consume_challenge(&self, wallet: &str) -> Option<Challenge> {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.remove(wallet)
    }
}

/// Validates a session token and returns (user_id, wallet_address, api_key).
pub fn validate_session_token(token: &str, api_key: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = token.splitn(2, '.').collect();
    if parts.len() != 2 { return None; }
    let payload_bytes = base64::engine::general_purpose::STANDARD.decode(parts[0]).ok()?;
    let payload = String::from_utf8(payload_bytes).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(api_key.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());
    if expected_sig != parts[1] { return None; }
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != 4 { return None; }
    let exp: i64 = fields[3].parse().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    if now > exp { return None; }
    Some((fields[0].to_string(), fields[1].to_string(), fields[2].to_string()))
}

/// Rebuild users list from token ledger merged with local users.
pub fn rebuild_users_from_ledger(ledger: &crate::token::TokenLedger, local: &[User]) -> Vec<User> {
    let mut merged = local.to_vec();
    for (wallet, name) in ledger.all_registered_accounts() {
        let wallet_owned = wallet.to_string();
        let name_owned = name.to_string();
        if !merged.iter().any(|u| u.wallet_address == wallet_owned) {
            merged.push(User {
                id: format!("u-{}", &wallet_owned[..8]),
                name: name_owned,
                api_key: String::new(),
                phrase_hash: String::new(),
                quota_bytes: default_quota_bytes(),
                wallet_address: wallet_owned.clone(),
                account_type: default_account_type(),
                org_id: String::new(),
                org_role: String::new(),
                discord_id: String::new(),
                discord_username: String::new(),
            });
        }
    }
    merged
}
