//! Sliding-Window Rate Limiter
//!
//! In-Memory Rate-Limiting per IP-Adresse oder Custom-Key.
//! Verwendet ein Sliding-Window-Verfahren: Innerhalb eines Zeitfensters
//! werden maximal N Anfragen erlaubt.
//!
//! ## Verwendung
//!
//! ```rust,ignore
//! use rate_limiter::RateLimiter;
//!
//! // 5 Anfragen pro 60 Sekunden
//! let limiter = RateLimiter::new(5, 60);
//!
//! if !limiter.check("192.168.1.1") {
//!     // 429 Too Many Requests zurückgeben
//! }
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

// ─── Rate Limiter ────────────────────────────────────────────────────────────

/// Thread-sicherer Sliding-Window Rate Limiter.
///
/// Speichert Timestamps der letzten Anfragen pro Key (IP oder Adresse)
/// und entscheidet ob eine neue Anfrage erlaubt wird.
pub struct RateLimiter {
    /// Maximale Anfragen innerhalb des Zeitfensters
    max_requests: u32,
    /// Zeitfenster in Sekunden
    window_secs: u64,
    /// Key → Liste der Timestamps (Sliding Window)
    entries: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    /// Erstellt einen neuen Rate Limiter.
    ///
    /// - `max_requests`: Maximale Anfragen pro Zeitfenster
    /// - `window_secs`: Zeitfenster in Sekunden
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        RateLimiter {
            max_requests,
            window_secs,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Prüft ob eine Anfrage für den gegebenen Key erlaubt ist.
    ///
    /// Gibt `true` zurück wenn die Anfrage erlaubt ist, `false` wenn das Limit
    /// überschritten wurde.
    ///
    /// Registriert die Anfrage automatisch wenn sie erlaubt wird.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let timestamps = entries.entry(key.to_string()).or_default();

        // Alte Einträge außerhalb des Fensters entfernen
        timestamps.retain(|ts| now.duration_since(*ts) < window);

        if timestamps.len() >= self.max_requests as usize {
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    /// Gibt die verbleibende Anzahl erlaubter Anfragen für einen Key zurück.
    #[allow(dead_code)]
    pub fn remaining(&self, key: &str) -> u32 {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let timestamps = entries.entry(key.to_string()).or_default();
        timestamps.retain(|ts| now.duration_since(*ts) < window);

        self.max_requests.saturating_sub(timestamps.len() as u32)
    }

    /// Gibt die Anzahl der Sekunden bis der älteste Eintrag aus dem Fenster fällt.
    ///
    /// Nützlich für `Retry-After` Header.
    pub fn retry_after_secs(&self, key: &str) -> u64 {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(timestamps) = entries.get(key) {
            if let Some(oldest) = timestamps.first() {
                let elapsed = now.duration_since(*oldest);
                if elapsed < window {
                    return (window - elapsed).as_secs() + 1;
                }
            }
        }
        0
    }

    /// Periodische Bereinigung: entfernt Keys ohne aktive Einträge.
    ///
    /// Sollte z.B. alle 5 Minuten aufgerufen werden um Memory-Leaks zu verhindern.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, timestamps| {
            timestamps.retain(|ts| now.duration_since(*ts) < window);
            !timestamps.is_empty()
        });
    }

    /// Aktuelle Anzahl getrackter Keys (für Monitoring).
    #[allow(dead_code)]
    pub fn tracked_keys(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ─── Rate Limit Konfiguration ────────────────────────────────────────────────

/// Vorkonfigurierte Rate Limiter für verschiedene Endpoints.
pub struct RateLimits {
    // ── Token-Endpunkte ──────────────────────────────────────────────────
    /// Faucet: 1 Anfrage pro 60 Sekunden
    pub faucet: RateLimiter,
    /// Token Transfer: 10 Anfragen pro 60 Sekunden
    pub transfer: RateLimiter,
    /// Wallet erstellen: 5 Anfragen pro 60 Sekunden
    pub wallet_create: RateLimiter,
    /// Key-Rotation: 2 Anfragen pro 300 Sekunden (5 Min)
    pub key_rotation: RateLimiter,

    // ── Auth-Endpunkte ───────────────────────────────────────────────────
    /// Signup: 5 Anfragen pro 5 Minuten pro IP
    pub auth_signup: RateLimiter,
    /// Login: 10 Anfragen pro 60 Sekunden pro IP
    pub auth_login: RateLimiter,

    // ── Chat ─────────────────────────────────────────────────────────────
    /// Chat-Nachrichten senden: 30 pro Minute pro User
    pub chat_send: RateLimiter,

    // ── Dokumente ────────────────────────────────────────────────────────
    /// Dokument-Upload: 10 pro Minute pro User
    pub document_upload: RateLimiter,

    // ── Trust ────────────────────────────────────────────────────────────
    /// Trust-Anfragen: 3 pro 5 Minuten pro IP
    pub trust_request: RateLimiter,

    // ── Catch-All ────────────────────────────────────────────────────────
    /// Allgemeine Schreib-Operationen: 60 pro Minute pro IP
    pub general_write: RateLimiter,

    // ── Updater (Peer-Sync) ──────────────────────────────────────────────
    /// Update-Chunk-Download: 30 Anfragen pro 60 Sekunden pro IP (U3 — Bandwidth-DoS-Schutz)
    pub update_chunk: RateLimiter,
}

impl RateLimits {
    /// Erstellt die Standard Rate-Limiter Konfiguration.
    pub fn new() -> Self {
        RateLimits {
            faucet: RateLimiter::new(1, 60),
            transfer: RateLimiter::new(10, 60),
            wallet_create: RateLimiter::new(5, 60),
            key_rotation: RateLimiter::new(2, 300),
            auth_signup: RateLimiter::new(5, 300),
            auth_login: RateLimiter::new(10, 60),
            chat_send: RateLimiter::new(30, 60),
            document_upload: RateLimiter::new(10, 60),
            trust_request: RateLimiter::new(3, 300),
            general_write: RateLimiter::new(60, 60),
            update_chunk: RateLimiter::new(30, 60),
        }
    }

    /// Periodische Bereinigung aller Rate Limiter.
    pub fn cleanup_all(&self) {
        self.faucet.cleanup();
        self.transfer.cleanup();
        self.wallet_create.cleanup();
        self.key_rotation.cleanup();
        self.auth_signup.cleanup();
        self.auth_login.cleanup();
        self.chat_send.cleanup();
        self.document_upload.cleanup();
        self.trust_request.cleanup();
        self.general_write.cleanup();
        self.update_chunk.cleanup();
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/// Extrahiert die Client-IP aus den Request-Headers.
///
/// Reihenfolge: `X-Forwarded-For` (erster Eintrag) → `X-Real-IP` → Fallback "unknown".
/// Wenn ein Reverse-Proxy (Nginx) vorgeschaltet ist, setzt dieser die Header.
pub fn extract_client_ip(headers: &HeaderMap) -> String {
    // X-Forwarded-For: "client, proxy1, proxy2" → erster Eintrag
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    // X-Real-IP (von Nginx gesetzt)
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = real_ip.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    "unknown".to_string()
}

/// Prüft das Rate-Limit und gibt bei Überschreitung eine 429-Response zurück.
///
/// Gibt `None` zurück wenn die Anfrage erlaubt ist, oder `Some(Response)` mit
/// einem JSON-Body und `Retry-After` Header.
///
/// Für Handler die `-> impl IntoResponse` mit `.into_response()` verwenden.
pub fn check_rate_limit(limiter: &RateLimiter, key: &str, endpoint: &str) -> Option<Response> {
    if limiter.check(key) {
        return None;
    }
    let retry = limiter.retry_after_secs(key);
    Some(
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from(retry as u64),
            )],
            axum::Json(json!({
                "ok": false,
                "error": format!("{endpoint}: Rate Limit überschritten. Retry in {retry}s."),
                "retry_after_secs": retry,
            })),
        )
            .into_response(),
    )
}

/// Tuple-Variante für Handler die `(StatusCode, Json<Value>)` zurückgeben.
///
/// Gleiche Logik wie [`check_rate_limit`], aber gibt ein Tuple zurück
/// statt einer fertig gebauten Response.
pub fn check_rate_limit_tuple(
    limiter: &RateLimiter,
    key: &str,
    endpoint: &str,
) -> Option<(StatusCode, axum::Json<serde_json::Value>)> {
    if limiter.check(key) {
        return None;
    }
    let retry = limiter.retry_after_secs(key);
    Some((
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(json!({
            "ok": false,
            "error": format!("{endpoint}: Rate Limit überschritten. Retry in {retry}s."),
            "retry_after_secs": retry,
        })),
    ))
}
