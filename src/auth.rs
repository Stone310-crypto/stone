use base64::Engine as _;
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    #[serde(default)]
    pub phrase_hash: String,
    #[serde(default = "default_quota_bytes")]
    pub quota_bytes: u64,
    /// StoneCoin Wallet-Adresse (Ed25519 Public Key Hex, 64 Zeichen).
    /// Wird automatisch bei der Registrierung aus der Mnemonic abgeleitet.
    #[serde(default)]
    pub wallet_address: String,
}

pub fn default_quota_bytes() -> u64 {
    5 * 1024 * 1024 * 1024
} // 5 GiB

#[derive(Deserialize)]
pub struct SignupRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub id: String,
    pub api_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
}

pub fn load_users() -> Arc<Mutex<Vec<User>>> {
    if let Ok(data) = fs::read_to_string(users_file()) {
        if let Ok(list) = serde_json::from_str::<Vec<User>>(&data) {
            return Arc::new(Mutex::new(list));
        }
    }
    Arc::new(Mutex::new(Vec::new()))
}

pub fn save_users(users: &[User]) {
    if let Ok(json) = serde_json::to_string_pretty(users) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(users_file(), json);
    }
}

pub fn generate_key() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn hash_phrase(phrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(phrase.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn create_user_with_phrase(name: &str) -> (User, String) {
    let phrase = Mnemonic::generate_in(Language::English, 12).expect("mnemonic gen");
    let phrase_str = phrase.to_string();
    let api_key = hash_phrase(&phrase_str);

    // Wallet-Adresse aus der Mnemonic ableiten (Ed25519 Public Key)
    let wallet_address = wallet_address_from_phrase(&phrase_str);

    let user = User {
        id: String::new(),
        name: name.to_string(),
        api_key: api_key.clone(),
        phrase_hash: api_key.clone(),
        quota_bytes: default_quota_bytes(),
        wallet_address,
    };
    (user, phrase_str)
}

pub fn create_user_with_random_phrase(name: &str) -> (User, String) {
    create_user_with_phrase(name)
}

/// Berechnet die StoneCoin Wallet-Adresse (Ed25519 Public Key Hex) aus einer BIP39-Mnemonic.
///
/// - 12 Wörter (16 Byte Entropy) → SHA-256 → 32 Byte → Ed25519 Signing Key → Public Key
/// - 24 Wörter (32 Byte Entropy) → direkt als Ed25519 Signing Key → Public Key
pub fn wallet_address_from_phrase(phrase: &str) -> String {
    use ed25519_dalek::SigningKey;

    let Ok(mnemonic) = Mnemonic::parse_in(Language::English, phrase) else {
        return String::new();
    };
    let entropy = mnemonic.to_entropy();

    // Gleiche Key-Derivation wie token::wallet::Wallet
    let key_bytes: [u8; 32] = if entropy.len() == 32 {
        entropy.try_into().unwrap()
    } else {
        // SHA-256 expandiert kürzere Entropy auf 32 Byte
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        hasher.finalize().into()
    };

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();
    hex::encode(verifying_key.as_bytes())
}

pub fn resolve_phrase(phrase: &str) -> Option<String> {
    if Mnemonic::parse_in(Language::English, phrase).is_err() {
        return None;
    }
    Some(hash_phrase(phrase))
}

/// Rekonstruiert die User-Liste aus dem On-Chain Account-Registry des Ledgers.
///
/// Der Ledger enthält alle AccountRegister-TXs mit name + api_key_hash + wallet_address.
/// Diese Funktion baut daraus die `Vec<User>` auf und mergt sie mit eventuell
/// vorhandenen lokalen Usern (Fallback für Alt-Accounts vor Chain-Registrierung).
///
/// Reihenfolge: Chain hat Vorrang. Lokale User ohne Chain-Eintrag bleiben erhalten
/// (Rückwärtskompatibilität), werden aber beim nächsten Login migriert.
pub fn rebuild_users_from_ledger(
    ledger: &crate::token::TokenLedger,
    existing_users: &[User],
) -> Vec<User> {
    let chain_accounts = ledger.all_registered_accounts();
    let mut users: Vec<User> = Vec::with_capacity(chain_accounts.len() + existing_users.len());

    // 1. Alle Chain-registrierten Accounts übernehmen
    let mut chain_wallets: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut chain_api_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut idx = 0usize;

    for (wallet, name) in chain_accounts {
        idx += 1;
        let api_key_hash = ledger.account_api_key_hash(wallet).unwrap_or("").to_string();

        // ID: Versuche aus bestehenden Usern zu übernehmen, sonst generieren
        let existing_id = existing_users.iter()
            .find(|u| u.wallet_address == *wallet || u.api_key == api_key_hash)
            .map(|u| u.id.clone());
        let id = existing_id.unwrap_or_else(|| format!("user-{}", idx));

        // Quota: aus bestehendem User übernehmen oder Default
        let quota = existing_users.iter()
            .find(|u| u.wallet_address == *wallet || u.api_key == api_key_hash)
            .map(|u| u.quota_bytes)
            .unwrap_or_else(default_quota_bytes);

        chain_wallets.insert(wallet.clone());
        if !api_key_hash.is_empty() {
            chain_api_keys.insert(api_key_hash.clone());
        }

        users.push(User {
            id,
            name: name.clone(),
            api_key: api_key_hash.clone(),
            phrase_hash: api_key_hash,
            quota_bytes: quota,
            wallet_address: wallet.clone(),
        });
    }

    // 2. Lokale User OHNE Chain-Eintrag beibehalten (Legacy-Kompatibilität)
    for u in existing_users {
        let already_in_chain = (!u.wallet_address.is_empty() && chain_wallets.contains(&u.wallet_address))
            || (!u.api_key.is_empty() && chain_api_keys.contains(&u.api_key));
        if !already_in_chain {
            users.push(u.clone());
        }
    }

    users
}

// ─── Lokale Token-Generierung (kein Auth-Server nötig) ───────────────────────

/// Claims für einen lokal generierten HMAC-Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTokenClaims {
    /// Node-ID (Subject)
    pub node_id: String,
    /// Ausstellungszeitpunkt (Unix-Sekunden)
    pub issued_at: u64,
    /// Ablaufzeitpunkt (Unix-Sekunden)
    pub expires_at: u64,
    /// Zufälliger Nonce (verhindert Replay-Angriffe)
    pub nonce: String,
}

impl LocalTokenClaims {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

/// Erzeugt einen lokal signierten HMAC-SHA256-Token für einen Node.
///
/// Format: `base64(json_claims).base64(hmac_signature)`
/// Der Token beweist, dass der Node den `cluster_key` kennt — kein
/// zentraler Auth-Server erforderlich.
pub fn generate_local_token(node_id: &str, cluster_key: &str, ttl_secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let claims = LocalTokenClaims {
        node_id: node_id.to_string(),
        issued_at: now,
        expires_at: now + ttl_secs,
        nonce: hex::encode(nonce_bytes),
    };

    let claims_json = serde_json::to_string(&claims).unwrap_or_default();
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(claims_json.as_bytes());

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cluster_key.as_bytes())
        .expect("HMAC akzeptiert beliebige Schlüssellängen");
    mac.update(claims_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

    format!("{claims_b64}.{sig_b64}")
}

/// Validiert einen lokal signierten Token.
/// Gibt `Some(claims)` zurück wenn Signatur + Ablaufzeit gültig sind.
pub fn validate_local_token(token: &str, cluster_key: &str) -> Option<LocalTokenClaims> {
    let parts: Vec<&str> = token.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let claims_b64 = parts[0];
    let sig_b64 = parts[1];

    // Signatur prüfen
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cluster_key.as_bytes()).ok()?;
    mac.update(claims_b64.as_bytes());
    let expected_sig = mac.finalize().into_bytes();
    let expected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_sig);
    if expected_b64 != sig_b64 {
        return None;
    }

    // Claims dekodieren
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_b64)
        .ok()?;
    let claims: LocalTokenClaims = serde_json::from_slice(&claims_bytes).ok()?;

    if claims.is_expired() {
        return None;
    }

    Some(claims)
}

