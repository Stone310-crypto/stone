//! Push-Notification-System — FCM v1 Integration für Android Push-Benachrichtigungen.
//!
//! Token-Store: `stone_data/push_tokens.json`
//! FCM Auth:    Google Service Account (`stone_data/firebase-sa.json`)

use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::blockchain::data_dir;

// ─── Push-Typen ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PushType {
    #[serde(rename = "new_message")]
    NewMessage,
    #[serde(rename = "payment_request")]
    PaymentRequest,
    #[serde(rename = "payment_confirmed")]
    PaymentConfirmed,
    #[serde(rename = "announcement")]
    Announcement,
    #[serde(rename = "incoming_call")]
    IncomingCall,
}

impl PushType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::NewMessage       => "new_message",
            Self::PaymentRequest   => "payment_request",
            Self::PaymentConfirmed => "payment_confirmed",
            Self::Announcement     => "announcement",
            Self::IncomingCall     => "incoming_call",
        }
    }

    pub fn title(&self) -> &str {
        match self {
            Self::NewMessage       => "Neue Nachricht",
            Self::PaymentRequest   => "Zahlungsanfrage",
            Self::PaymentConfirmed => "Zahlung bestätigt",
            Self::Announcement     => "Community Announcement",
            Self::IncomingCall     => "Eingehender Anruf",
        }
    }

    pub fn priority(&self) -> &str {
        match self {
            Self::NewMessage | Self::PaymentRequest | Self::PaymentConfirmed => "HIGH",
            Self::Announcement => "HIGH",
            Self::IncomingCall => "HIGH",
        }
    }
}

// ─── Platform ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Android,
    Ios,
}

// ─── Token-Eintrag ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushToken {
    pub wallet_hash: String,
    pub fcm_token: String,
    pub platform: Platform,
    /// Unix-Timestamp der letzten Registrierung/Aktualisierung
    pub updated_at: i64,
}

// ─── Token-Store ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PushTokenStore {
    pub tokens: HashMap<String, PushToken>,
}

impl PushTokenStore {
    pub fn register(&mut self, wallet_hash: String, fcm_token: String, platform: Platform) {
        self.tokens.insert(wallet_hash.clone(), PushToken {
            wallet_hash,
            fcm_token,
            platform,
            updated_at: chrono::Utc::now().timestamp(),
        });
    }

    pub fn unregister(&mut self, wallet_hash: &str) -> bool {
        self.tokens.remove(wallet_hash).is_some()
    }

    pub fn get_token(&self, wallet_hash: &str) -> Option<&PushToken> {
        self.tokens.get(wallet_hash)
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

// ─── Persistenz ──────────────────────────────────────────────────────────────

fn push_tokens_file() -> String {
    format!("{}/push_tokens.json", data_dir())
}

pub fn load_push_tokens() -> PushTokenStore {
    if let Ok(data) = fs::read_to_string(push_tokens_file()) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        PushTokenStore::default()
    }
}

pub fn save_push_tokens(store: &PushTokenStore) {
    if let Ok(json) = serde_json::to_string_pretty(store) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(push_tokens_file(), json);
    }
}

// ─── FCM v1 Client ──────────────────────────────────────────────────────────

fn firebase_sa_file() -> String {
    format!("{}/firebase-sa.json", data_dir())
}

#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
}

/// Cached OAuth2 Access Token
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

pub struct FcmClient {
    sa: Option<ServiceAccount>,
    http: reqwest::Client,
    cached_token: Arc<Mutex<Option<CachedToken>>>,
}

impl FcmClient {
    pub fn new() -> Self {
        let sa = fs::read_to_string(firebase_sa_file())
            .ok()
            .and_then(|data| serde_json::from_str::<ServiceAccount>(&data).ok());

        if sa.is_none() {
            eprintln!("[push] ⚠ firebase-sa.json nicht gefunden – Push deaktiviert");
        }

        Self {
            sa,
            http: reqwest::Client::new(),
            cached_token: Arc::new(Mutex::new(None)),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.sa.is_some()
    }

    /// OAuth2 Access Token für FCM v1 API generieren (JWT → Google Token Endpoint)
    async fn get_access_token(&self) -> Option<String> {
        let sa = self.sa.as_ref()?;

        // Prüfen ob cached token noch gültig (5 Min Buffer)
        {
            let cache = self.cached_token.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref ct) = *cache {
                if Instant::now() < ct.expires_at {
                    return Some(ct.access_token.clone());
                }
            }
        }

        // Neuen JWT erzeugen
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": sa.client_email,
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        });

        // RSA-Key aus PEM extrahieren
        let key = match jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[push] RSA-Key-Fehler: {e}");
                return None;
            }
        };

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let jwt = match jsonwebtoken::encode(&header, &claims, &key) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[push] JWT-Fehler: {e}");
                return None;
            }
        };

        // JWT gegen Google Token Endpoint tauschen
        let resp = self.http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .ok()?;

        #[derive(Deserialize)]
        struct TokenResp {
            access_token: String,
            expires_in: u64,
        }

        let token_resp: TokenResp = resp.json().await.ok()?;

        // Cachen (5 Min vor Ablauf erneuern)
        let expires_at = Instant::now() + Duration::from_secs(token_resp.expires_in.saturating_sub(300));
        let access_token = token_resp.access_token.clone();
        {
            let mut cache = self.cached_token.lock().unwrap_or_else(|e| e.into_inner());
            *cache = Some(CachedToken { access_token: access_token.clone(), expires_at });
        }

        Some(access_token)
    }

    /// Push an ein einzelnes Gerät senden
    pub async fn send_push(&self, fcm_token: &str, push_type: &PushType) -> bool {
        self.send_push_with_body(fcm_token, push_type, "").await
    }

    /// Push an ein einzelnes Gerät senden – mit optionalem Body-Text
    pub async fn send_push_with_body(&self, fcm_token: &str, push_type: &PushType, body: &str) -> bool {
        let sa = match &self.sa {
            Some(sa) => sa,
            None => return false,
        };

        let access_token = match self.get_access_token().await {
            Some(t) => t,
            None => {
                eprintln!("[push] Kein Access Token – Push übersprungen");
                return false;
            }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            sa.project_id
        );

        let notification_body = if body.is_empty() {
            push_type.title().to_string()
        } else {
            body.to_string()
        };

        let payload = serde_json::json!({
            "message": {
                "token": fcm_token,
                "notification": {
                    "title": push_type.title(),
                    "body": notification_body,
                },
                "android": {
                    "priority": push_type.priority(),
                    "ttl": "86400s",
                    "notification": {
                        "channel_id": match push_type {
                            PushType::NewMessage => "stone_messages",
                            PushType::PaymentRequest | PushType::PaymentConfirmed => "stone_payments",
                            PushType::Announcement => "stone_social",
                            PushType::IncomingCall => "stone_calls",
                        },
                    },
                },
                "data": {
                    "type": push_type.as_str(),
                    "title": push_type.title(),
                    "body": body,
                }
            }
        });

        match self.http
            .post(&url)
            .bearer_auth(&access_token)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let resp_body = resp.text().await.unwrap_or_default();
                if !status.is_success() {
                    eprintln!("[push] ❌ FCM-Fehler {status}: {resp_body}");
                    return false;
                }
                println!("[push] ✅ FCM {status} → {}: {resp_body}", push_type.as_str());
                true
            }
            Err(e) => {
                eprintln!("[push] ❌ HTTP-Fehler: {e}");
                false
            }
        }
    }

    /// Push an alle registrierten Geräte senden (für Announcements)
    pub async fn broadcast(&self, store: &PushTokenStore, push_type: &PushType) -> usize {
        self.broadcast_with_body(store, push_type, "").await
    }

    /// Push an alle registrierten Geräte senden – mit Body-Text
    pub async fn broadcast_with_body(&self, store: &PushTokenStore, push_type: &PushType, body: &str) -> usize {
        if !self.is_configured() { return 0; }
        let mut sent = 0;
        for token in store.tokens.values() {
            if self.send_push_with_body(&token.fcm_token, push_type, body).await {
                sent += 1;
            }
        }
        sent
    }

    /// Push an eine bestimmte Wallet senden
    pub async fn notify_wallet(&self, store: &PushTokenStore, wallet: &str, push_type: &PushType) -> bool {
        self.notify_wallet_with_body(store, wallet, push_type, "").await
    }

    /// Push an eine bestimmte Wallet senden – mit Body-Text
    pub async fn notify_wallet_with_body(&self, store: &PushTokenStore, wallet: &str, push_type: &PushType, body: &str) -> bool {
        if !self.is_configured() { return false; }
        let wallet_hash = hash_wallet(wallet);
        match store.get_token(&wallet_hash) {
            Some(token) => self.send_push_with_body(&token.fcm_token, push_type, body).await,
            None => false,
        }
    }

    /// Eingehenden Anruf an eine Wallet melden (mit call_id und from_wallet im data-Payload)
    pub async fn notify_wallet_incoming_call(
        &self,
        store: &PushTokenStore,
        to_wallet: &str,
        from_wallet: &str,
        from_name: &str,
        call_id: &str,
    ) -> bool {
        if !self.is_configured() { return false; }
        let wallet_hash = hash_wallet(to_wallet);
        let fcm_token = match store.get_token(&wallet_hash) {
            Some(t) => t.fcm_token.clone(),
            None => return false,
        };

        let sa = match &self.sa {
            Some(sa) => sa,
            None => return false,
        };
        let access_token = match self.get_access_token().await {
            Some(t) => t,
            None => {
                eprintln!("[push] Kein Access Token – Call-Push übersprungen");
                return false;
            }
        };
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            sa.project_id
        );
        let caller_display = if from_name.is_empty() {
            &from_wallet[..from_wallet.len().min(12)]
        } else {
            from_name
        };
        let payload = serde_json::json!({
            "message": {
                "token": fcm_token,
                "notification": {
                    "title": "Eingehender Anruf",
                    "body": caller_display,
                },
                "android": {
                    "priority": "HIGH",
                    "ttl": "60s",
                    "notification": {
                        "channel_id": "stone_calls",
                    },
                },
                "data": {
                    "type": "incoming_call",
                    "title": "Eingehender Anruf",
                    "body": caller_display,
                    "call_id": call_id,
                    "from_wallet": from_wallet,
                    "from_name": from_name,
                }
            }
        });
        match self.http
            .post(&url)
            .bearer_auth(&access_token)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    eprintln!("[push] ❌ Call-Push FCM-Fehler {status}: {body}");
                    return false;
                }
                println!("[push] 📞 Call-Push an {} → {call_id}", &to_wallet[..to_wallet.len().min(12)]);
                true
            }
            Err(e) => {
                eprintln!("[push] ❌ Call-Push HTTP-Fehler: {e}");
                false
            }
        }
    }
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/// SHA256-Hash einer Wallet-Adresse erzeugen (Privatsphäre)
pub fn hash_wallet(wallet: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(wallet.as_bytes());
    hex::encode(hasher.finalize())
}
