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

        let mut entries = self.entries.lock().unwrap();
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
    pub fn remaining(&self, key: &str) -> u32 {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entries = self.entries.lock().unwrap();
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

        let entries = self.entries.lock().unwrap();
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

        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, timestamps| {
            timestamps.retain(|ts| now.duration_since(*ts) < window);
            !timestamps.is_empty()
        });
    }

    /// Aktuelle Anzahl getrackter Keys (für Monitoring).
    pub fn tracked_keys(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

// ─── Rate Limit Konfiguration ────────────────────────────────────────────────

/// Vorkonfigurierte Rate Limiter für verschiedene Endpoints.
pub struct RateLimits {
    /// Faucet: 1 Anfrage pro 60 Sekunden
    pub faucet: RateLimiter,
    /// Token Transfer: 10 Anfragen pro 60 Sekunden
    pub transfer: RateLimiter,
    /// Wallet erstellen: 5 Anfragen pro 60 Sekunden
    pub wallet_create: RateLimiter,
    /// Key-Rotation: 2 Anfragen pro 300 Sekunden (5 Min)
    pub key_rotation: RateLimiter,
}

impl RateLimits {
    /// Erstellt die Standard Rate-Limiter Konfiguration.
    pub fn new() -> Self {
        RateLimits {
            faucet: RateLimiter::new(1, 60),           // 1 pro Minute
            transfer: RateLimiter::new(10, 60),        // 10 pro Minute
            wallet_create: RateLimiter::new(5, 60),    // 5 pro Minute
            key_rotation: RateLimiter::new(2, 300),    // 2 pro 5 Minuten
        }
    }

    /// Periodische Bereinigung aller Rate Limiter.
    pub fn cleanup_all(&self) {
        self.faucet.cleanup();
        self.transfer.cleanup();
        self.wallet_create.cleanup();
        self.key_rotation.cleanup();
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        Self::new()
    }
}
