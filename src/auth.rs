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
    #[serde(default)]
    pub phrase_hash: String,
    #[serde(default = "default_quota_bytes")]
    pub quota_bytes: u64,
    /// StoneCoin Wallet-Adresse (Ed25519 Public Key Hex, 64 Zeichen).
    /// Wird automatisch bei der Registrierung aus der Mnemonic abgeleitet.
    #[serde(default)]
    pub wallet_address: String,
    /// Account-Typ: "private" (Standard) oder "organization"
    #[serde(default = "default_account_type")]
    pub account_type: String,
    /// Organisation-ID, der dieser User angehört (leer = keine)
    #[serde(default)]
    pub org_id: String,
    /// Rolle innerhalb der Organisation (leer, "owner", "admin", "member", "viewer")
    #[serde(default)]
    pub org_role: String,
}

pub fn default_account_type() -> String { "private".to_string() }

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
        account_type: default_account_type(),
        org_id: String::new(),
        org_role: String::new(),
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
        match entropy.try_into() {
            Ok(b) => b,
            Err(_) => return String::new(),
        }
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
    let mut _idx = 0usize;

    for (wallet, name) in chain_accounts {
        _idx += 1;
        let api_key_hash = ledger.account_api_key_hash(wallet).unwrap_or("").to_string();

        // ID: Versuche aus bestehenden Usern zu übernehmen, sonst generieren
        let existing_id = existing_users.iter()
            .find(|u| u.wallet_address == *wallet || u.api_key == api_key_hash)
            .map(|u| u.id.clone());
        let id = existing_id.unwrap_or_else(|| {
            format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"))
        });

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
            account_type: default_account_type(),
            org_id: String::new(),
            org_role: String::new(),
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

// ─── Challenge-Response Authentifizierung (Cross-Platform Login) ─────────────

/// Ein vom Server generierter Challenge-Nonce für die Wallet-basierte Authentifizierung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Zufälliger 32-Byte Nonce (hex-codiert)
    pub nonce: String,
    /// Wallet-Adresse für die dieser Challenge gilt
    pub wallet_address: String,
    /// Erstellungszeitpunkt (Unix-Sekunden)
    pub created_at: u64,
    /// Ablaufzeitpunkt (Unix-Sekunden) — Standard: 5 Minuten
    pub expires_at: u64,
}

impl AuthChallenge {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

/// In-Memory Store für aktive Challenges. Thread-safe via Arc<Mutex<>>.
#[derive(Clone)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, AuthChallenge>>>,
}

/// Challenge-Gültigkeit in Sekunden (5 Minuten)
pub const CHALLENGE_TTL_SECS: u64 = 300;
/// Session-Token-Gültigkeit in Sekunden (24 Stunden)
pub const SESSION_TOKEN_TTL_SECS: u64 = 86400;

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Erzeugt einen neuen Challenge-Nonce für eine Wallet-Adresse.
    /// Ein vorheriger Challenge für dieselbe Wallet wird überschrieben.
    pub fn create_challenge(&self, wallet_address: &str) -> AuthChallenge {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nonce_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let challenge = AuthChallenge {
            nonce: hex::encode(nonce_bytes),
            wallet_address: wallet_address.to_string(),
            created_at: now,
            expires_at: now + CHALLENGE_TTL_SECS,
        };

        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Aufräumen: abgelaufene Challenges entfernen
        map.retain(|_, c| !c.is_expired());
        map.insert(wallet_address.to_string(), challenge.clone());
        challenge
    }

    /// Konsumiert und validiert einen Challenge für eine Wallet-Adresse.
    /// Gibt `Some(challenge)` zurück wenn gültig, `None` wenn abgelaufen oder unbekannt.
    /// Der Challenge wird nach einmaliger Nutzung gelöscht (Replay-Schutz).
    pub fn consume_challenge(&self, wallet_address: &str) -> Option<AuthChallenge> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let challenge = map.remove(wallet_address)?;
        if challenge.is_expired() {
            return None;
        }
        Some(challenge)
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifiziert eine Ed25519-Signatur des Challenge-Nonce gegen die bekannte Wallet-Adresse.
///
/// - `wallet_address`: Hex-codierter Ed25519 Public Key (64 Zeichen)
/// - `nonce`: Der vom Server ausgegebene Challenge-Nonce (hex)
/// - `signature`: Hex-codierte Ed25519-Signatur des Nonce
///
/// Gibt `true` zurück wenn die Signatur gültig ist.
pub fn verify_challenge_signature(
    wallet_address: &str,
    nonce: &str,
    signature: &str,
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    // Wallet-Adresse (= Public Key) dekodieren
    let Ok(pubkey_bytes) = hex::decode(wallet_address) else {
        return false;
    };
    let Ok(pubkey_array): Result<[u8; 32], _> = pubkey_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_array) else {
        return false;
    };

    // Signatur dekodieren
    let Ok(sig_bytes) = hex::decode(signature) else {
        return false;
    };
    let Ok(sig_array): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_array);

    // Verifizierung: Nonce-Bytes als Message
    use ed25519_dalek::Verifier;
    verifying_key.verify(nonce.as_bytes(), &sig).is_ok()
}

// ─── Session-Token (für authentifizierte Cross-Platform Sessions) ────────────

/// Claims für einen Session-Token (nach erfolgreichem Challenge-Response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// User-ID
    pub user_id: String,
    /// Wallet-Adresse
    pub wallet_address: String,
    /// Ausstellungszeitpunkt (Unix-Sekunden)
    pub issued_at: u64,
    /// Ablaufzeitpunkt (Unix-Sekunden)
    pub expires_at: u64,
    /// Zufälliger Nonce (Replay-Schutz)
    pub nonce: String,
}

impl SessionClaims {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

/// Erzeugt einen HMAC-signierten Session-Token nach erfolgreichem Challenge-Response.
///
/// Format: `base64(json_claims).base64(hmac_sha256_signature)`
/// Der `cluster_key` wird als HMAC-Schlüssel verwendet.
pub fn generate_session_token(
    user_id: &str,
    wallet_address: &str,
    cluster_key: &str,
    ttl_secs: u64,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let claims = SessionClaims {
        user_id: user_id.to_string(),
        wallet_address: wallet_address.to_string(),
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

/// Validiert einen Session-Token und gibt die Claims zurück.
pub fn validate_session_token(token: &str, cluster_key: &str) -> Option<SessionClaims> {
    let parts: Vec<&str> = token.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let claims_b64 = parts[0];
    let sig_b64 = parts[1];

    // HMAC-Signatur prüfen
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
    let claims: SessionClaims = serde_json::from_slice(&claims_bytes).ok()?;

    if claims.is_expired() {
        return None;
    }

    Some(claims)
}

// ─── QR-Code Login (Cross-Device Authentifizierung) ──────────────────────────
//
// Flow:
//   1. Website/Desktop → POST /auth/qr/create → erhält { login_token, expires_in }
//   2. Website zeigt QR-Code mit login_token (+ server URL)
//   3. Website pollt → GET /auth/qr/status/:token → wartet auf Freigabe
//   4. iOS App scannt QR → FaceID → POST /auth/qr/approve { login_token }
//      (mit Bearer-Token des bereits eingeloggten iOS-Users)
//   5. Server markiert QR-Session als "approved" mit session_token + user
//   6. Website erhält beim nächsten Poll: { approved, session_token, user }

/// QR-Login-Session Gültigkeit in Sekunden (3 Minuten)
pub const QR_LOGIN_TTL_SECS: u64 = 180;

/// Status einer QR-Login-Session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QrLoginStatus {
    /// QR-Code angezeigt, wartet auf Scan
    Pending,
    /// iOS App hat QR gescannt, Benutzer bestätigt per FaceID
    Approved,
    /// Abgelaufen oder ungültig
    Expired,
}

/// Eine QR-Login-Session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrLoginSession {
    /// Eindeutiger Login-Token (wird im QR-Code codiert)
    pub login_token: String,
    /// Status der Session
    pub status: QrLoginStatus,
    /// Erstellungszeitpunkt (Unix-Sekunden)
    pub created_at: u64,
    /// Ablaufzeitpunkt (Unix-Sekunden)
    pub expires_at: u64,
    /// Session-Token (wird nach Genehmigung gesetzt)
    pub session_token: Option<String>,
    /// User-Daten (wird nach Genehmigung gesetzt)
    pub approved_user_id: Option<String>,
    pub approved_user_name: Option<String>,
    pub approved_wallet: Option<String>,
    pub approved_account_type: Option<String>,
    /// Mnemonic-Phrase (wird nach Genehmigung gesetzt, nur für QR-Login Chat)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_phrase: Option<String>,
}

impl QrLoginSession {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

/// In-Memory Store für aktive QR-Login-Sessions. Thread-safe via Arc<Mutex<>>.
#[derive(Clone)]
pub struct QrLoginStore {
    inner: Arc<Mutex<HashMap<String, QrLoginSession>>>,
}

impl QrLoginStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Erzeugt eine neue QR-Login-Session.
    /// Gibt den `login_token` zurück, der im QR-Code codiert wird.
    pub fn create_session(&self) -> QrLoginSession {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);

        let session = QrLoginSession {
            login_token: hex::encode(token_bytes),
            status: QrLoginStatus::Pending,
            created_at: now,
            expires_at: now + QR_LOGIN_TTL_SECS,
            session_token: None,
            approved_user_id: None,
            approved_user_name: None,
            approved_wallet: None,
            approved_account_type: None,
            approved_phrase: None,
        };

        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Aufräumen: abgelaufene Sessions entfernen
        map.retain(|_, s| !s.is_expired());
        map.insert(session.login_token.clone(), session.clone());
        session
    }

    /// Fragt den Status einer QR-Login-Session ab.
    /// Gibt `None` zurück wenn unbekannt oder abgelaufen.
    pub fn get_status(&self, login_token: &str) -> Option<QrLoginSession> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Aufräumen
        map.retain(|_, s| !s.is_expired());
        map.get(login_token).cloned()
    }

    /// Genehmigt eine QR-Login-Session (vom iOS-App-User).
    /// Setzt session_token + user-daten + optional phrase. Gibt `true` zurück bei Erfolg.
    pub fn approve_session(
        &self,
        login_token: &str,
        session_token: String,
        user: &User,
        phrase: Option<String>,
    ) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = map.get_mut(login_token) {
            if session.is_expired() || session.status != QrLoginStatus::Pending {
                return false;
            }
            session.status = QrLoginStatus::Approved;
            session.session_token = Some(session_token);
            session.approved_user_id = Some(user.id.clone());
            session.approved_user_name = Some(user.name.clone());
            session.approved_wallet = Some(user.wallet_address.clone());
            session.approved_account_type = Some(user.account_type.clone());
            session.approved_phrase = phrase;
            true
        } else {
            false
        }
    }

    /// Konsumiert eine genehmigte Session (Website holt das Token ab).
    /// Nach dem Abruf wird die Session gelöscht (einmalig verwendbar).
    pub fn consume_approved(&self, login_token: &str) -> Option<QrLoginSession> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let session = map.get(login_token)?;
        if session.status != QrLoginStatus::Approved {
            return None;
        }
        map.remove(login_token)
    }
}

impl Default for QrLoginStore {
    fn default() -> Self {
        Self::new()
    }
}

