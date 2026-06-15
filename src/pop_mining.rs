//! Proof-of-Play (PoP) Mining
//!
//! Replaces classical PoW. Instead of wasting CPU, players "find blocks" by
//! playing the game. The randomness comes from the current chain tip (oracle),
//! making it impossible for the plugin to predict or pre-compute block finds.
//!
//! Protocol per slot (60 seconds):
//!   1. Plugin fetches challenge: chain_tip_hash + slot_id + difficulty_target
//!   2. Plugin computes VRF output = Ed25519_sign(proof_key, SHA-256(vrf_input))
//!      where vrf_input = chain_tip_hash | player_wallet | slot_id | server_id
//!   3. Plugin checks SHA-256(vrf_output)[0..4] < difficulty_target (big-endian u32)
//!   4. If found: plugin submits proof to node
//!   5. Node independently verifies Ed25519 sig, difficulty, slot freshness, activity
//!   6. Node credits STONE to player wallet

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Length of each mining slot in seconds.
pub const SLOT_DURATION_SECS: u64 = 60;

/// Default difficulty target (big-endian u32, first 4 bytes of SHA-256(vrf_output) must be <).
/// 0x0FFFFFFF ≈ 6.25% probability per slot — high for easy testing.
/// Lower for production: 0x0028F5C2 ≈ 0.1%, 0x00028F5C ≈ 0.01%.
pub const DEFAULT_DIFFICULTY_TARGET: &str = "0FFFFFFF";

/// STONE reward per block find (fixed).
pub const POP_BLOCK_REWARD: f64 = 10.0;

/// Minimum gameplay events a player must have in the current slot to be eligible.
pub const MIN_ACTIVITY_EVENTS: u32 = 3;

/// Slots are considered expired after this many seconds have passed.
const SLOT_GRACE_SECS: u64 = 30;

// ── Challenge ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopChallenge {
    /// SHA-256 hash of the latest chain block.
    pub chain_tip_hash: String,
    /// Sequential slot number = unix_timestamp / SLOT_DURATION_SECS.
    pub slot_id: u64,
    /// Unix timestamp when this slot expires.
    pub slot_expires_at: i64,
    /// 8 hex chars (4-byte big-endian u32). SHA-256(vrf_output)[0..4] must be < this.
    pub difficulty_target: String,
    /// Minimum gameplay events required in this slot.
    pub min_activity_events: u32,
}

// ── Proof submitted by plugin ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopProof {
    /// game_id matching the SDK key.
    pub game_id: String,
    /// Stone wallet address (stone1...) of the player.
    pub player_wallet: String,
    /// Slot the VRF was computed for.
    pub slot_id: u64,
    /// Hex: SHA-256(chain_tip_hash + "|" + player_wallet + "|" + slot_id + "|" + game_id).
    pub vrf_input_hash: String,
    /// Hex: Ed25519 signature of vrf_input_hash (64 bytes = 128 hex chars).
    pub vrf_output: String,
    /// Hex: Ed25519 public key of the plugin's proof key (32 bytes = 64 hex chars).
    pub plugin_pubkey: String,
    /// Hex: SHA-256 of the plugin JAR.
    pub plugin_hash: String,
    /// Number of gameplay events in this slot (block breaks, mob kills, …).
    pub activity_event_count: u32,
    /// Unix timestamp of submission.
    pub timestamp: i64,
}

// ── Verification result ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopVerifyResult {
    pub ok: bool,
    pub reward_stone: Option<f64>,
    /// Human-readable rejection reason when ok = false.
    pub error: Option<String>,
}

// ── PoP Mining State ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct PopMiningInner {
    /// Configurable difficulty target (can be updated without restart).
    difficulty_target: String,
    min_activity_events: u32,
    /// Already-claimed slots: key = "<slot_id>:<player_wallet>:<game_id>".
    claimed_slots: HashSet<String>,
    /// Per-game plugin hash allow-list. Empty = accept any (permissive default).
    allowed_hashes: HashMap<String, HashSet<String>>,
    total_finds: u64,
    total_rewarded_stone: f64,
    /// Last time each game server reported player mining activity.
    /// Used by BlockTimer to decide whether to produce an auto-block.
    active_game_servers: HashMap<String, Instant>,
}

#[derive(Debug, Clone)]
pub struct PopMiningState {
    inner: Arc<Mutex<PopMiningInner>>,
}

impl Default for PopMiningState {
    fn default() -> Self {
        Self::new()
    }
}

impl PopMiningState {
    pub fn new() -> Self {
        let difficulty_target = std::env::var("STONE_POP_DIFFICULTY")
            .unwrap_or_else(|_| DEFAULT_DIFFICULTY_TARGET.to_string());
        let min_activity_events = std::env::var("STONE_POP_MIN_EVENTS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(MIN_ACTIVITY_EVENTS);
        eprintln!(
            "[pop-mining] difficulty={difficulty_target} min_events={min_activity_events} slot_secs={SLOT_DURATION_SECS}"
        );
        Self {
            inner: Arc::new(Mutex::new(PopMiningInner {
                difficulty_target,
                min_activity_events,
                claimed_slots: HashSet::new(),
                allowed_hashes: HashMap::new(),
                total_finds: 0,
                total_rewarded_stone: 0.0,
                active_game_servers: HashMap::new(),
            })),
        }
    }

    pub fn current_params(&self) -> (String, u32) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.difficulty_target.clone(), g.min_activity_events)
    }

    pub fn stats(&self) -> (u64, f64) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.total_finds, g.total_rewarded_stone)
    }

    /// Records that a Minecraft game server has active players mining.
    /// Called by the plugin whenever a player breaks a block (throttled to ~1/15s).
    /// This is used by the BlockTimer to suppress auto-blocks while players are active.
    pub fn record_activity(&self, game_id: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.active_game_servers.insert(game_id.to_string(), Instant::now());
    }

    /// Returns true if any game server reported mining activity within `timeout_secs`.
    /// The BlockTimer uses this to decide whether to pause the auto-block countdown.
    pub fn has_recent_activity(&self, timeout_secs: u64) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Remove stale entries (> 2× timeout) to avoid unbounded growth.
        g.active_game_servers.retain(|_, t| t.elapsed().as_secs() < timeout_secs * 2);
        g.active_game_servers
            .values()
            .any(|t| t.elapsed().as_secs() < timeout_secs)
    }

    /// Returns the count of currently active game server miners.
    pub fn active_server_count(&self, timeout_secs: u64) -> usize {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.active_game_servers
            .values()
            .filter(|t| t.elapsed().as_secs() < timeout_secs)
            .count()
    }

    /// Register an allowed plugin hash for a specific game.
    /// Call this when a game admin registers a new plugin version.
    pub fn register_hash(&self, game_id: &str, hash_hex: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.allowed_hashes
            .entry(game_id.to_string())
            .or_default()
            .insert(hash_hex.to_lowercase());
    }

    /// Verify a PoP proof. Returns the STONE reward amount on success.
    ///
    /// `chain_tip_hash` must be the hash of the block at the time the slot started.
    pub fn verify_proof(
        &self,
        proof: &PopProof,
        chain_tip_hash: &str,
    ) -> PopVerifyResult {
        let err = |msg: &str| PopVerifyResult {
            ok: false,
            reward_stone: None,
            error: Some(msg.to_string()),
        };

        // 1. Slot freshness
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expected_slot = now_secs / SLOT_DURATION_SECS;
        // Accept current slot or the immediately previous one (grace period for network latency).
        if proof.slot_id != expected_slot && proof.slot_id + 1 != expected_slot {
            return err(&format!(
                "Slot abgelaufen: eingereicht={} erwartet={} (±1)",
                proof.slot_id, expected_slot
            ));
        }

        // 2. Activity minimum
        let (difficulty_target, min_activity) = self.current_params();
        if proof.activity_event_count < min_activity {
            return err(&format!(
                "Zu wenig Aktivität: {} Events, Minimum={}",
                proof.activity_event_count, min_activity
            ));
        }

        // 3. Duplicate claim check
        let claim_key = format!("{}:{}:{}", proof.slot_id, proof.player_wallet, proof.game_id);
        {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.claimed_slots.contains(&claim_key) {
                return err("Slot bereits eingelöst (double-claim)");
            }

            // 4. Plugin hash allow-list (if configured)
            let allowed = g.allowed_hashes.get(&proof.game_id);
            if let Some(set) = allowed {
                if !set.is_empty() && !set.contains(&proof.plugin_hash.to_lowercase()) {
                    return err("Plugin-Hash nicht in der erlaubten Liste");
                }
            }
        }

        // 5. Decode plugin public key
        let pub_bytes = match hex::decode(&proof.plugin_pubkey) {
            Ok(b) if b.len() == 32 => b,
            Ok(b) => return err(&format!("plugin_pubkey muss 32 Bytes sein, war {}", b.len())),
            Err(e) => return err(&format!("plugin_pubkey kein gültiges Hex: {e}")),
        };
        let pub_arr: [u8; 32] = pub_bytes.try_into().expect("Länge geprüft");
        let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(k) => k,
            Err(e) => return err(&format!("VerifyingKey ungültig: {e}")),
        };

        // 6. Decode VRF output (signature)
        let sig_bytes = match hex::decode(&proof.vrf_output) {
            Ok(b) if b.len() == 64 => b,
            Ok(b) => return err(&format!("vrf_output muss 64 Bytes sein, war {}", b.len())),
            Err(e) => return err(&format!("vrf_output kein gültiges Hex: {e}")),
        };
        let sig_arr: [u8; 64] = sig_bytes.clone().try_into().expect("Länge geprüft");
        let signature = Signature::from_bytes(&sig_arr);

        // 7. Recompute expected VRF input hash and verify it matches submitted hash
        let vrf_input_str = format!(
            "{}|{}|{}|{}",
            chain_tip_hash, proof.player_wallet, proof.slot_id, proof.game_id
        );
        let expected_vrf_input_hash = Sha256::digest(vrf_input_str.as_bytes());
        let expected_hex = hex::encode(expected_vrf_input_hash);
        if expected_hex != proof.vrf_input_hash.to_lowercase() {
            return err(&format!(
                "vrf_input_hash stimmt nicht: erwartet={} eingereicht={}",
                expected_hex, proof.vrf_input_hash
            ));
        }

        // 8. Verify Ed25519 signature over vrf_input_hash
        let vrf_input_bytes = match hex::decode(&proof.vrf_input_hash) {
            Ok(b) => b,
            Err(e) => return err(&format!("vrf_input_hash kein gültiges Hex: {e}")),
        };
        if verifying_key.verify(&vrf_input_bytes, &signature).is_err() {
            return err("Ed25519-Signatur (vrf_output) ungültig");
        }

        // 9. Check difficulty: SHA-256(vrf_output)[0..4] < difficulty_target
        let vrf_hash = Sha256::digest(&sig_bytes);
        let hash_prefix = u32::from_be_bytes(vrf_hash[0..4].try_into().expect("4 bytes"));
        let target = match u32::from_str_radix(&difficulty_target, 16) {
            Ok(t) => t,
            Err(_) => return err("Ungültiges difficulty_target auf Serverseite"),
        };
        if hash_prefix >= target {
            return err(&format!(
                "Difficulty nicht erreicht: hash_prefix=0x{:08X} target=0x{target:08X}",
                hash_prefix
            ));
        }

        // 10. Mark slot as claimed and record stats
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.claimed_slots.insert(claim_key);
            g.total_finds += 1;
            g.total_rewarded_stone += POP_BLOCK_REWARD;

            // Prune old claimed slots (keep only last 10 000 entries to avoid unbounded growth)
            if g.claimed_slots.len() > 10_000 {
                g.claimed_slots.clear();
            }
        }

        eprintln!(
            "[pop-mining] ✅ Block gefunden! game={} player_wallet={} slot={} hash_prefix=0x{:08X} reward={}",
            proof.game_id,
            proof.player_wallet,
            proof.slot_id,
            hash_prefix,
            POP_BLOCK_REWARD,
        );

        PopVerifyResult {
            ok: true,
            reward_stone: Some(POP_BLOCK_REWARD),
            error: None,
        }
    }
}

// ── Slot helpers ───────────────────────────────────────────────────────────────

pub fn current_slot_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / SLOT_DURATION_SECS
}

pub fn slot_expires_at(slot_id: u64) -> i64 {
    ((slot_id + 1) * SLOT_DURATION_SECS + SLOT_GRACE_SECS) as i64
}
