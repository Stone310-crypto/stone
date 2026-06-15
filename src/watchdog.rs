//! Proof-of-Client-Hash – Watchdog-Modul
//!
//! Verifiziert, dass ein Minecraft-Plugin unverändert ist und keine
//! verdächtigen JVM-Agenten oder Debugger geladen hat.
//!
//! Ablauf:
//!   1. Plugin berechnet SHA-256 seines eigenen JARs
//!   2. Plugin sammelt System-Fingerprint (JVM, OS, Prozesse)
//!   3. Plugin signiert Hash+Fingerprint+Timestamp mit Ed25519-Wallet-Key
//!   4. Node verifiziert Signatur und prüft Hash gegen Known-Good-Liste
//!   5. Node gibt TrustLevel zurück: Full / Ok / Reduced / Rejected

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

/// Maximaler erlaubter Zeitstempel-Drift (±5 Minuten).
const MAX_TIMESTAMP_DRIFT_SECS: i64 = 300;
/// Anzahl Violations bis ein Spieler als "flagged" gilt.
const VIOLATION_FLAG_THRESHOLD: u32 = 3;

// ─── Payload vom Plugin ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHashProof {
    /// game_id des registrierten Spiels
    pub game_id: String,
    /// SHA-256 (hex) des Plugin-JARs
    pub plugin_hash: String,
    /// SHA-256 (hex) der System-Infos (JVM, OS, CPU-Anzahl)
    pub system_fingerprint: String,
    /// Unix-Zeitstempel in Sekunden (muss frisch sein)
    pub timestamp: i64,
    /// Erkannte verdächtige Merkmale (z. B. "DEBUGGER_DETECTED", "AGENT_LOADED:...")
    pub suspicious_flags: Vec<String>,
    /// Ed25519-Signatur (128 hex-Zeichen, 64 Bytes) über sign_input
    pub signature: String,
    /// Ed25519 Public Key (64 hex-Zeichen, 32 Bytes) des Plugin-Proof-Keys
    pub public_key_hex: String,
}

// ─── Vertrauensstufe ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Hash in Known-Good-Liste, Signatur ok, keine verdächtigen Flags
    Full,
    /// Signatur ok, Hash noch nicht in Known-Good-Liste (Erstregistrierung)
    Ok,
    /// Signatur ok, aber verdächtige Flags (Debugger / Agent)
    Reduced,
    /// Signatur ungültig, Timestamp zu alt oder Public Key defekt
    Rejected,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Ok => write!(f, "ok"),
            Self::Reduced => write!(f, "reduced"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

// ─── Verifizieter Client ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerifiedClient {
    pub plugin_hash: String,
    pub last_seen: i64,
    pub trust_level: TrustLevel,
    pub total_proofs: u64,
    pub suspicious_count: u32,
}

// ─── Behavior Report (Verhaltens-Violation) ───────────────────────────────────

#[derive(Debug, Clone)]
pub enum ViolationType {
    Xray,
    AutoClicker,
    ReachHack,
    Unknown(String),
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Xray => write!(f, "XRAY"),
            Self::AutoClicker => write!(f, "AUTO_CLICKER"),
            Self::ReachHack => write!(f, "REACH_HACK"),
            Self::Unknown(s) => write!(f, "UNKNOWN({s})"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ViolationType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.as_str() {
            "XRAY" => Self::Xray,
            "AUTO_CLICKER" => Self::AutoClicker,
            "REACH_HACK" => Self::ReachHack,
            other => Self::Unknown(other.to_string()),
        })
    }
}

impl serde::Serialize for ViolationType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SingleViolation {
    pub player_id: String,
    pub player_name: String,
    pub game_id: String,
    pub violation: String,
    pub confidence: f64,
    pub details: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BehaviorReport {
    pub game_id: String,
    pub violations: Vec<SingleViolation>,
}

/// Aggregierter Spieler-Verstoß-Zähler.
#[derive(Debug, Clone, Default)]
pub struct PlayerViolationState {
    pub player_name: String,
    pub xray_count: u32,
    pub auto_clicker_count: u32,
    pub reach_hack_count: u32,
    pub total_violations: u32,
    pub last_seen: i64,
    pub flagged: bool,
}

// ─── Watchdog State ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct WatchdogInner {
    /// Bekannte gültige Plugin-Hashes (optional, aus Env-Var).
    known_good_hashes: HashSet<String>,
    /// Zuletzt verifiziete Clients, key = public_key_hex.
    verified_clients: HashMap<String, VerifiedClient>,
    /// Spieler-Verstoß-Tracker, key = player_id (UUID).
    player_violations: HashMap<String, PlayerViolationState>,
}

impl Default for WatchdogInner {
    fn default() -> Self {
        Self {
            known_good_hashes: HashSet::new(),
            verified_clients: HashMap::new(),
            player_violations: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WatchdogState {
    inner: Arc<Mutex<WatchdogInner>>,
}

impl Default for WatchdogState {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchdogState {
    /// Erstellt einen neuen WatchdogState.
    ///
    /// Known-Good-Hashes werden aus `STONE_WATCHDOG_KNOWN_HASHES` geladen
    /// (kommagetrennte SHA-256-Hex-Strings). Leer = alle Hashes als "ok" akzeptieren.
    pub fn new() -> Self {
        let known_good_hashes: HashSet<String> = std::env::var("STONE_WATCHDOG_KNOWN_HASHES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| s.len() == 64)
            .collect();

        if !known_good_hashes.is_empty() {
            eprintln!(
                "[watchdog] {} bekannte Plugin-Hashes geladen",
                known_good_hashes.len()
            );
        }

        Self {
            inner: Arc::new(Mutex::new(WatchdogInner {
                known_good_hashes,
                verified_clients: HashMap::new(),
                player_violations: HashMap::new(),
            })),
        }
    }

    /// Verifiziert einen Client-Proof.
    ///
    /// Returns: `(TrustLevel, Option<Fehlermeldung>)`
    pub fn verify_proof(&self, proof: &ClientHashProof) -> (TrustLevel, Option<String>) {
        // 1. Timestamp-Frische prüfen
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let drift = (now - proof.timestamp).abs();
        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            return (
                TrustLevel::Rejected,
                Some(format!("Timestamp zu alt/neu (drift={drift}s, max={MAX_TIMESTAMP_DRIFT_SECS}s)")),
            );
        }

        // 2. Public Key dekodieren
        let pub_bytes = match hex::decode(&proof.public_key_hex) {
            Ok(b) if b.len() == 32 => b,
            Ok(b) => {
                return (
                    TrustLevel::Rejected,
                    Some(format!("public_key_hex muss 32 Bytes ergeben, war {} Bytes", b.len())),
                )
            }
            Err(e) => return (TrustLevel::Rejected, Some(format!("public_key_hex kein gültiges Hex: {e}"))),
        };
        let pub_arr: [u8; 32] = pub_bytes.try_into().expect("Länge geprüft");
        let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(k) => k,
            Err(e) => return (TrustLevel::Rejected, Some(format!("VerifyingKey ungültig: {e}"))),
        };

        // 3. Signatur dekodieren
        let sig_bytes = match hex::decode(&proof.signature) {
            Ok(b) if b.len() == 64 => b,
            Ok(b) => {
                return (
                    TrustLevel::Rejected,
                    Some(format!("Signatur muss 64 Bytes ergeben, war {} Bytes", b.len())),
                )
            }
            Err(e) => return (TrustLevel::Rejected, Some(format!("Signatur kein gültiges Hex: {e}"))),
        };
        let sig_arr: [u8; 64] = sig_bytes.try_into().expect("Länge geprüft");
        let signature = Signature::from_bytes(&sig_arr);

        // 4. sign_input = SHA-256(plugin_hash | "|" | system_fingerprint | "|" | timestamp)
        //    Muss exakt mit der Java-Seite übereinstimmen.
        let sign_input = format!(
            "{}|{}|{}",
            proof.plugin_hash, proof.system_fingerprint, proof.timestamp
        );
        let sign_hash = Sha256::digest(sign_input.as_bytes());

        if verifying_key.verify(sign_hash.as_slice(), &signature).is_err() {
            return (TrustLevel::Rejected, Some("Ed25519-Signatur ungültig".into()));
        }

        // 5. Trust Level bestimmen
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let hash_lower = proof.plugin_hash.to_lowercase();
        let hash_known = guard.known_good_hashes.is_empty()
            || guard.known_good_hashes.contains(&hash_lower);
        let has_suspicious = !proof.suspicious_flags.is_empty();

        let trust = match (hash_known, has_suspicious) {
            (true, false) => TrustLevel::Full,
            (_, true) => TrustLevel::Reduced,
            (false, false) => TrustLevel::Ok,
        };

        // 6. Client-State aktualisieren
        let entry = guard
            .verified_clients
            .entry(proof.public_key_hex.clone())
            .or_insert_with(|| VerifiedClient {
                plugin_hash: proof.plugin_hash.clone(),
                last_seen: proof.timestamp,
                trust_level: trust.clone(),
                total_proofs: 0,
                suspicious_count: 0,
            });
        entry.plugin_hash = proof.plugin_hash.clone();
        entry.last_seen = proof.timestamp;
        entry.trust_level = trust.clone();
        entry.total_proofs += 1;
        if has_suspicious {
            entry.suspicious_count += 1;
        }

        (trust, None)
    }

    pub fn verified_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .verified_clients
            .len()
    }

    /// Speichert eine Batch-Liste von Verhaltens-Violations.
    /// Gibt zurück: Anzahl neu geflaggter Spieler.
    pub fn record_violations(&self, report: &BehaviorReport) -> u32 {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut newly_flagged = 0u32;

        for v in &report.violations {
            let state = guard
                .player_violations
                .entry(v.player_id.clone())
                .or_insert_with(|| PlayerViolationState {
                    player_name: v.player_name.clone(),
                    ..Default::default()
                });

            state.player_name = v.player_name.clone();
            state.last_seen = v.timestamp;
            state.total_violations += 1;

            match v.violation.as_str() {
                "XRAY"         => state.xray_count += 1,
                "AUTO_CLICKER" => state.auto_clicker_count += 1,
                "REACH_HACK"   => state.reach_hack_count += 1,
                _              => {}
            }

            if !state.flagged && state.total_violations >= VIOLATION_FLAG_THRESHOLD {
                state.flagged = true;
                newly_flagged += 1;
                eprintln!(
                    "[watchdog] 🚨 Spieler FLAGGED: {} (id={}) xray={} clicker={} reach={}",
                    state.player_name,
                    v.player_id,
                    state.xray_count,
                    state.auto_clicker_count,
                    state.reach_hack_count,
                );
            }
        }

        newly_flagged
    }

    pub fn is_player_flagged(&self, player_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .player_violations
            .get(player_id)
            .map(|s| s.flagged)
            .unwrap_or(false)
    }

    pub fn flagged_player_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .player_violations
            .values()
            .filter(|s| s.flagged)
            .count()
    }
}
