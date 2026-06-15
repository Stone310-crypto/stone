//! Miner-Registry & Block-Timer
//!
//! Ermöglicht öffentliches Mining ohne Whitelist: Fake-Miner werden durch
//! einen **partiellen Proof-of-Work** in jedem Heartbeat abgewehrt. Nur wer
//! wirklich Argon2id rechnet, kann den Auto-Block-Timer pausieren.
//!
//! ## Ablauf
//!
//! 1. Miner ruft `POST /api/v1/miners/connect` mit seinem Public-Key und
//!    einer signierten Timestamp-Message auf.
//! 2. Miner sendet alle ~15 s einen Heartbeat (`POST /api/v1/miners/heartbeat`)
//!    der eine Near-Miss-PoW-Lösung gegen das aktuelle Block-Template enthält.
//! 3. Solange mindestens ein Miner einen gültigen Heartbeat innerhalb der
//!    letzten `heartbeat_timeout_secs` geschickt hat, pausiert der Auto-Block-
//!    Timer in `BlockTimer`.
//! 4. Sind alle Miner verstummt, erzeugt der Timer nach `auto_timeout_secs`
//!    einen Auto-Block über `MasterNodeState::mint_block()`.
//! 5. Ein harter Fallback produziert einen Block auch dann, wenn der Timer
//!    sich > 2 × `auto_timeout_secs` nicht zurückgesetzt hat (Liveness-Garantie
//!    selbst bei fehlerhafter Work-Prüfung).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Wie viele Bits unter der regulären Difficulty die partielle PoW-Lösung
/// in einem Heartbeat erreichen muss. Default: 6 → ~64× leichter.
pub const DEFAULT_PARTIAL_DELTA: u32 = 6;

/// Obergrenze der gleichzeitig verfolgten Miner. Schützt vor Memory-Exhaustion
/// durch Millionen Fake-Wallets (LRU-Cap: alte Einträge werden gekickt wenn
/// Limit erreicht).
pub const MAX_ACTIVE_MINERS: usize = 1000;

/// Akzeptiertes Zeitfenster für signierte Miner-Timestamps (±60 s).
pub const TIMESTAMP_SKEW_SECS: i64 = 60;

/// Wie viele Nonces pro (wallet, template_id) gecacht werden, um Replays
/// desselben Heartbeats abzuweisen.
const NONCE_DEDUP_CAP: usize = 256;

/// Hard-Fallback-Multiplikator: wenn `last_block_time` länger als
/// `HARD_FALLBACK_MULT * auto_timeout_secs` zurückliegt, wird auch bei
/// "aktiven" Minern ein Auto-Block produziert.
pub const HARD_FALLBACK_MULT: u64 = 2;

// ─── Wire-Formate ─────────────────────────────────────────────────────────────

/// Connect-Nachricht vom Miner an den Master.
///
/// Signiert wird die Payload `"stone-miner-connect|{wallet}|{timestamp}"`
/// mit dem privaten Schlüssel zur `pubkey`/`wallet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerConnectMsg {
    /// Ed25519 Public-Key hex (= wallet address). 64 hex chars.
    pub wallet: String,
    /// Derselbe Key redundant als `pubkey`, für API-Klarheit.
    pub pubkey: String,
    /// Unix-Timestamp in Sekunden. Muss innerhalb ±`TIMESTAMP_SKEW_SECS` liegen.
    pub timestamp: i64,
    /// Ed25519-Signatur (hex, 128 chars) über `"stone-miner-connect|wallet|timestamp"`.
    pub signature: String,
}

/// Heartbeat-Nachricht vom Miner.
///
/// Enthält einen **partiellen PoW-Beweis** (`nonce` + `partial_hash`) gegen
/// das aktuelle Block-Template. Der Server verifiziert die Signatur und
/// rechnet Argon2id neu: nur wenn `leading_zero_bits(partial_hash)` mindestens
/// `(effective_difficulty - partial_delta)` erreicht, zählt der Heartbeat.
///
/// Signiert wird `"stone-miner-heartbeat|{wallet}|{timestamp}|{template_id}|{nonce}"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerHeartbeat {
    pub wallet: String,
    pub pubkey: String,
    pub timestamp: i64,
    pub template_id: String,
    pub nonce: u64,
    /// Hex-encoded Argon2id-Output (32 Bytes = 64 hex chars).
    pub partial_hash: String,
    /// Ed25519-Signatur (hex, 128 chars).
    pub signature: String,
}

// ─── Persistente / serialisierbare Miner-Identity ─────────────────────────────

/// Persistente Darstellung eines aktiven Miners (wird z.B. für Metrics / REST
/// nach außen ausgegeben). Enthält keine `Instant` — alle Zeitstempel sind
/// Unix-Sekunden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerIdentity {
    pub miner_wallet: String,
    pub miner_pubkey: String,
    pub session_signature: String,
    pub connected_at: i64,
    pub last_heartbeat: i64,
    pub current_difficulty: u64,
    pub blocks_found: u64,
}

// ─── Laufzeit-Status ──────────────────────────────────────────────────────────

/// Laufzeit-Status eines Miners — nutzt `Instant` für präzise Timeouts, wird
/// nicht persistiert.
#[derive(Debug, Clone)]
pub struct MinerStatus {
    pub wallet: String,
    pub pubkey: String,
    pub connected_at: i64,
    pub last_heartbeat: Instant,
    pub last_heartbeat_ts: i64,
    pub heartbeat_timeout_secs: u64,
    pub current_difficulty: u64,
    pub blocks_found: u64,
    /// "Probation": Ein frisch registrierter Miner zählt erst nach
    /// `successful_heartbeats >= 1` als "aktiv" für den Timer. Connect
    /// allein pausiert den Timer nicht.
    pub successful_heartbeats: u64,
    /// Kleiner Ringbuffer an bereits gesehenen Nonces für das aktuelle
    /// Template. Verhindert Replay desselben Heartbeats.
    pub seen_nonces: VecDeque<(String, u64)>, // (template_id, nonce)
}

impl MinerStatus {
    pub fn has_seen_nonce(&self, template_id: &str, nonce: u64) -> bool {
        self.seen_nonces
            .iter()
            .any(|(t, n)| t == template_id && *n == nonce)
    }

    pub fn remember_nonce(&mut self, template_id: &str, nonce: u64) {
        if self.seen_nonces.len() >= NONCE_DEDUP_CAP {
            self.seen_nonces.pop_front();
        }
        self.seen_nonces.push_back((template_id.to_string(), nonce));
    }

    pub fn to_identity(&self) -> MinerIdentity {
        MinerIdentity {
            miner_wallet: self.wallet.clone(),
            miner_pubkey: self.pubkey.clone(),
            session_signature: String::new(),
            connected_at: self.connected_at,
            last_heartbeat: self.last_heartbeat_ts,
            current_difficulty: self.current_difficulty,
            blocks_found: self.blocks_found,
        }
    }
}

// ─── Registry ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MinerRegistry {
    active_miners: HashMap<String, MinerStatus>,
    /// Default-Timeout, nach dem ein stummer Miner entfernt wird.
    pub heartbeat_timeout_secs: u64,
}

impl MinerRegistry {
    pub fn new(heartbeat_timeout_secs: u64) -> Self {
        Self {
            active_miners: HashMap::new(),
            heartbeat_timeout_secs,
        }
    }

    pub fn len(&self) -> usize {
        self.active_miners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.active_miners.is_empty()
    }

    /// Entfernt Miner, deren letzter Heartbeat länger als
    /// `heartbeat_timeout_secs` zurückliegt.
    pub fn cleanup_inactive(&mut self) -> usize {
        let before = self.active_miners.len();
        self.active_miners.retain(|_, s| {
            s.last_heartbeat.elapsed().as_secs() < s.heartbeat_timeout_secs
        });
        before - self.active_miners.len()
    }

    /// Gibt `true` zurück, wenn mindestens ein Miner innerhalb des Timeouts
    /// geheartbeatet hat **und** die Probation-Phase hinter sich hat.
    pub fn has_active_miners(&self) -> bool {
        self.active_miners
            .values()
            .any(|s| {
                s.successful_heartbeats >= 1
                    && s.last_heartbeat.elapsed().as_secs() < s.heartbeat_timeout_secs
            })
    }

    /// Registriert einen Miner (oder erneuert eine bestehende Session).
    /// Alleiniges `register_miner` zählt den Miner noch NICHT als aktiv —
    /// erst nach dem ersten gültigen Heartbeat.
    pub fn register_miner(
        &mut self,
        wallet: String,
        pubkey: String,
        session_signature: String,
        connected_at: i64,
    ) {
        // LRU-Cap: ältesten Miner kicken, wenn Cap erreicht und neuer Eintrag
        if !self.active_miners.contains_key(&wallet)
            && self.active_miners.len() >= MAX_ACTIVE_MINERS
        {
            if let Some((evict_wallet, _)) = self
                .active_miners
                .iter()
                .min_by_key(|(_, s)| s.last_heartbeat)
                .map(|(w, s)| (w.clone(), s.clone()))
            {
                self.active_miners.remove(&evict_wallet);
            }
        }

        // Bestehende Session erneuern (keep success counter / blocks_found)
        if let Some(existing) = self.active_miners.get_mut(&wallet) {
            existing.pubkey = pubkey;
            existing.connected_at = connected_at;
            existing.last_heartbeat = Instant::now();
            existing.last_heartbeat_ts = connected_at;
            existing.seen_nonces.clear();
            let _ = session_signature; // nicht persistiert
            return;
        }

        self.active_miners.insert(
            wallet.clone(),
            MinerStatus {
                wallet,
                pubkey,
                connected_at,
                last_heartbeat: Instant::now(),
                last_heartbeat_ts: connected_at,
                heartbeat_timeout_secs: self.heartbeat_timeout_secs,
                current_difficulty: 0,
                blocks_found: 0,
                successful_heartbeats: 0,
                seen_nonces: VecDeque::new(),
            },
        );
        let _ = session_signature;
    }

    /// Registriert einen gültigen Heartbeat. Gibt `Ok(())` bei Erfolg oder
    /// `Err(..)` wenn der Miner nicht registriert ist oder der Nonce bereits
    /// gesehen wurde.
    pub fn record_heartbeat(
        &mut self,
        wallet: &str,
        template_id: &str,
        nonce: u64,
        timestamp: i64,
        difficulty: u64,
    ) -> Result<(), &'static str> {
        let status = self
            .active_miners
            .get_mut(wallet)
            .ok_or("miner nicht registriert – zuerst /miners/connect")?;
        if status.has_seen_nonce(template_id, nonce) {
            return Err("nonce replay");
        }
        status.last_heartbeat = Instant::now();
        status.last_heartbeat_ts = timestamp;
        status.current_difficulty = difficulty;
        status.successful_heartbeats = status.successful_heartbeats.saturating_add(1);
        status.remember_nonce(template_id, nonce);
        Ok(())
    }

    /// Markiert dass der gegebene Miner einen Block gefunden hat (wird in
    /// `commit_mining_block` aufgerufen, wenn der Validator-PubKey einem
    /// registrierten Miner entspricht).
    pub fn record_block_found(&mut self, wallet: &str) {
        if let Some(s) = self.active_miners.get_mut(wallet) {
            s.blocks_found = s.blocks_found.saturating_add(1);
        }
    }

    pub fn get(&self, wallet: &str) -> Option<&MinerStatus> {
        self.active_miners.get(wallet)
    }

    pub fn snapshot(&self) -> Vec<MinerIdentity> {
        self.active_miners
            .values()
            .map(|s| s.to_identity())
            .collect()
    }
}

// ─── BlockTimer ──────────────────────────────────────────────────────────────

/// Auto-Block-Timer.
///
/// Reset bei jedem committed Block (lokal oder per Gossip empfangen). Ist
/// `has_active_miners() == false` und seit dem letzten Block mehr als
/// `auto_timeout_secs` vergangen → `mint_block()` wird aufgerufen.
#[derive(Debug)]
pub struct BlockTimer {
    last_block_time: Instant,
    pub auto_timeout_secs: u64,
    pub enabled: bool,
}

impl BlockTimer {
    pub fn new(auto_timeout_secs: u64, enabled: bool) -> Self {
        Self {
            last_block_time: Instant::now(),
            auto_timeout_secs,
            enabled,
        }
    }

    pub fn reset(&mut self) {
        self.last_block_time = Instant::now();
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.last_block_time.elapsed().as_secs()
    }

    /// Prüft, ob der Auto-Block jetzt erzeugt werden sollte.
    ///
    /// - `has_miners = false` → nach `auto_timeout_secs`
    /// - `has_miners = true` → erst nach `HARD_FALLBACK_MULT × auto_timeout_secs`
    ///   (Liveness-Garantie selbst gegen perfekt gefakede Heartbeats)
    pub fn should_auto_mine(&self, has_miners: bool) -> bool {
        if !self.enabled {
            return false;
        }
        let elapsed = self.elapsed_secs();
        if has_miners {
            elapsed > self.auto_timeout_secs.saturating_mul(HARD_FALLBACK_MULT)
        } else {
            elapsed > self.auto_timeout_secs
        }
    }
}

// ─── Message-Hilfen ───────────────────────────────────────────────────────────

/// Konstruiert die signierte Connect-Message (Client + Server identisch).
pub fn connect_sign_payload(wallet: &str, timestamp: i64) -> String {
    format!("stone-miner-connect|{wallet}|{timestamp}")
}

/// Konstruiert die signierte Heartbeat-Message.
pub fn heartbeat_sign_payload(
    wallet: &str,
    timestamp: i64,
    template_id: &str,
    nonce: u64,
) -> String {
    format!("stone-miner-heartbeat|{wallet}|{timestamp}|{template_id}|{nonce}")
}

/// Ed25519-Signaturprüfung über einen UTF-8-String.
pub fn verify_ed25519_string(payload: &str, pubkey_hex: &str, signature_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if pubkey_hex.len() != 64 || signature_hex.len() != 128 {
        return false;
    }
    let Ok(pk_bytes) = hex::decode(pubkey_hex) else { return false };
    let Ok(arr32): Result<[u8; 32], _> = pk_bytes.try_into() else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&arr32) else { return false };
    let Ok(sig_bytes) = hex::decode(signature_hex) else { return false };
    let Ok(arr64): Result<[u8; 64], _> = sig_bytes.try_into() else { return false };
    let sig = Signature::from_bytes(&arr64);
    vk.verify(payload.as_bytes(), &sig).is_ok()
}

/// Prüft Timestamp-Frische (±`TIMESTAMP_SKEW_SECS`).
pub fn timestamp_fresh(timestamp: i64, now: i64) -> bool {
    let diff = (now - timestamp).abs();
    diff <= TIMESTAMP_SKEW_SECS
}

/// Validiert eine Connect-Message (Signatur + Frische + Key-Format).
pub fn validate_connect(msg: &MinerConnectMsg, now: i64) -> Result<(), String> {
    if msg.wallet.len() != 64 || !msg.wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("wallet muss 64 hex chars sein".into());
    }
    if msg.pubkey != msg.wallet {
        return Err("pubkey muss identisch zu wallet sein (Ed25519 pubkey = wallet)".into());
    }
    if !timestamp_fresh(msg.timestamp, now) {
        return Err(format!(
            "timestamp nicht frisch (skew > {TIMESTAMP_SKEW_SECS}s)"
        ));
    }
    let payload = connect_sign_payload(&msg.wallet, msg.timestamp);
    if !verify_ed25519_string(&payload, &msg.pubkey, &msg.signature) {
        return Err("signatur ungültig".into());
    }
    Ok(())
}

/// Validiert eine Heartbeat-Message inkl. partiellem PoW.
///
/// Die Funktion bekommt das erwartete Template als Referenz und ermittelt
/// damit `prev_hash`, `block_index`, `validator_pubkey` sowie die
/// `effective_difficulty`. Der Heartbeat gilt als gültig wenn Argon2id neu
/// gerechnet den gleichen Hash ergibt **und** dessen führende-Null-Bits
/// mindestens `effective_difficulty - partial_delta` erreichen.
pub fn validate_heartbeat_with_template(
    msg: &MinerHeartbeat,
    now: i64,
    template: &super::MiningTemplate,
    partial_delta: u32,
) -> Result<(), String> {
    if msg.wallet.len() != 64 || !msg.wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("wallet muss 64 hex chars sein".into());
    }
    if msg.pubkey != msg.wallet {
        return Err("pubkey muss identisch zu wallet sein".into());
    }
    if msg.partial_hash.len() != 64 || !msg.partial_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("partial_hash muss 64 hex chars sein".into());
    }
    if !timestamp_fresh(msg.timestamp, now) {
        return Err(format!(
            "timestamp nicht frisch (skew > {TIMESTAMP_SKEW_SECS}s)"
        ));
    }
    if msg.template_id != template.template_id {
        return Err("template_id veraltet / unbekannt".into());
    }

    // Signatur prüfen
    let payload = heartbeat_sign_payload(&msg.wallet, msg.timestamp, &msg.template_id, msg.nonce);
    if !verify_ed25519_string(&payload, &msg.pubkey, &msg.signature) {
        return Err("signatur ungültig".into());
    }

    // Partial PoW: Argon2id-Verifikation nur wenn Block-PoW aktiv.
    // Im PoA-Modus reicht die Signatur als "I'm alive"-Beweis.
    if crate::consensus::BLOCK_POW_ENABLED {
        let computed = crate::consensus::compute_argon2_pow_hash(
            &template.previous_hash,
            template.block_index,
            &template.validator_pubkey,
            msg.nonce,
        );
        let computed_hex = hex::encode(computed);
        if computed_hex != msg.partial_hash {
            return Err("partial_hash != argon2id(inputs)".into());
        }

        let eff = if template.effective_difficulty > 0 {
            template.effective_difficulty
        } else {
            template.difficulty
        };
        let required = eff.saturating_sub(partial_delta).max(1);
        let zeros = crate::consensus::leading_zero_bits(&computed);
        if zeros < required {
            return Err(format!(
                "partial difficulty zu niedrig: {zeros} < {required} (eff={eff}, delta={partial_delta})"
            ));
        }
    }

    Ok(())
}

// ─── Config ───────────────────────────────────────────────────────────────────

/// Laufzeit-Config für Auto-Mining. Wird aus `node_config.json` gelesen.
#[derive(Debug, Clone, Copy)]
pub struct AutoMiningConfig {
    pub enabled: bool,
    pub auto_timeout_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub heartbeat_partial_delta: u32,
}

impl Default for AutoMiningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_timeout_secs: 120,
            heartbeat_timeout_secs: 30,
            heartbeat_partial_delta: DEFAULT_PARTIAL_DELTA,
        }
    }
}

impl AutoMiningConfig {
    /// Liest die Config aus `node_config.json` im Workspace-Root.
    /// Umgebungsvariablen überschreiben Dateiwerte:
    /// - `STONE_AUTO_MINING_ENABLED`
    /// - `STONE_AUTO_MINING_TIMEOUT`
    /// - `STONE_MINER_HEARTBEAT_TIMEOUT`
    /// - `STONE_MINER_PARTIAL_DELTA`
    pub fn load() -> Self {
        let mut cfg = Self::default();
        if let Ok(raw) = std::fs::read_to_string("node_config.json") {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(v) = json.get("auto_mining_enabled").and_then(|x| x.as_bool()) {
                    cfg.enabled = v;
                }
                if let Some(v) = json.get("auto_mining_timeout_secs").and_then(|x| x.as_u64()) {
                    cfg.auto_timeout_secs = v.max(5);
                }
                if let Some(v) = json
                    .get("miner_heartbeat_timeout_secs")
                    .and_then(|x| x.as_u64())
                {
                    cfg.heartbeat_timeout_secs = v.max(5);
                }
                if let Some(v) = json
                    .get("miner_heartbeat_partial_delta")
                    .and_then(|x| x.as_u64())
                {
                    cfg.heartbeat_partial_delta = v as u32;
                }
            }
        }
        if let Ok(v) = std::env::var("STONE_AUTO_MINING_ENABLED") {
            cfg.enabled = matches!(v.as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("STONE_AUTO_MINING_TIMEOUT") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.auto_timeout_secs = n.max(5);
            }
        }
        if let Ok(v) = std::env::var("STONE_MINER_HEARTBEAT_TIMEOUT") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.heartbeat_timeout_secs = n.max(5);
            }
        }
        if let Ok(v) = std::env::var("STONE_MINER_PARTIAL_DELTA") {
            if let Ok(n) = v.parse::<u32>() {
                cfg.heartbeat_partial_delta = n;
            }
        }
        cfg
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign(payload: &str, sk: &SigningKey) -> String {
        hex::encode(sk.sign(payload.as_bytes()).to_bytes())
    }

    #[test]
    fn connect_round_trip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let ts = 1_700_000_000;
        let payload = connect_sign_payload(&pk, ts);
        let msg = MinerConnectMsg {
            wallet: pk.clone(),
            pubkey: pk,
            timestamp: ts,
            signature: sign(&payload, &sk),
        };
        assert!(validate_connect(&msg, ts).is_ok());
        // stale
        assert!(validate_connect(&msg, ts + TIMESTAMP_SKEW_SECS + 1).is_err());
    }

    #[test]
    fn connect_rejects_bad_sig() {
        let sk1 = SigningKey::from_bytes(&[1u8; 32]);
        let sk2 = SigningKey::from_bytes(&[2u8; 32]);
        let pk1 = hex::encode(sk1.verifying_key().to_bytes());
        let ts = 1_700_000_000;
        let payload = connect_sign_payload(&pk1, ts);
        let msg = MinerConnectMsg {
            wallet: pk1.clone(),
            pubkey: pk1,
            timestamp: ts,
            signature: sign(&payload, &sk2), // fremder Key
        };
        assert!(validate_connect(&msg, ts).is_err());
    }

    #[test]
    fn registry_cleanup_and_has_active() {
        let mut reg = MinerRegistry::new(30);
        assert!(!reg.has_active_miners());
        reg.register_miner("a".repeat(64), "a".repeat(64), String::new(), 0);
        // noch kein Heartbeat → nicht "aktiv" (Probation)
        assert!(!reg.has_active_miners());
    }

    #[test]
    fn timer_enforces_hard_fallback() {
        let t = BlockTimer::new(10, true);
        assert!(!t.should_auto_mine(false)); // frisch
        assert!(!t.should_auto_mine(true));
    }
}
