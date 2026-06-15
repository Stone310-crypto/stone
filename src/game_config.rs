//! Game Configuration Storage
//!
//! Speichert von Game-Plugins (z.B. Minecraft) hochgeladene Konfigurationen
//! als JSON-Dateien in `stone_data/game_configs/{game_id}.json`.
//!
//! Die Plugins senden ihre Konfiguration periodisch per SDK-Key authentifiziert
//! an den Node. Der Node validiert die Struktur und speichert sie.
//! StoneScan liest die Konfiguration über einen öffentlichen Endpoint aus.
//!
//! ## Datei-Layout
//!
//! ```json
//! {
//!   "game_id": "mc-pop-test",
//!   "uploaded_at": 1717000000,
//!   "uploaded_by": "<pubkey>",
//!   "drops": {
//!     "chance": 0.10,
//!     "player_cooldown_secs": 5,
//!     "tiers": { "STONE": 1, "COAL_ORE": 1, "DIAMOND_ORE": 8, ... }
//!   },
//!   "mobs": {
//!     "chance": 0.20,
//!     "player_cooldown_secs": 3,
//!     "tiers": { "ZOMBIE": 1, "ENDER_DRAGON": 256, ... }
//!   },
//!   "rare_block": {
//!     "enabled": true,
//!     "material": "CRYING_OBSIDIAN",
//!     "find_chance": 0.0005,
//!     "drop_cooldown_secs": 15,
//!     "shard_reward": 32
//!   },
//!   "redeem": {
//!     "limit_mode": "per_day",
//!     "max_coins": 5
//!   },
//!   "scoreboard": { "enabled": true, "title": "Stone-Coins" },
//!   "death_protect": { "coins": true, "shards": true },
//!   "anti_dupe": { "scan_interval_seconds": 120 }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::blockchain::data_dir;

/// Maximale Anzahl gespeicherter Config-Historien pro Spiel.
const MAX_HISTORY: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropTierConfig {
    pub chance: f64,
    #[serde(default)]
    pub player_cooldown_secs: u64,
    #[serde(default)]
    pub tiers: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RareBlockConfig {
    pub enabled: bool,
    #[serde(default)]
    pub material: String,
    pub find_chance: f64,
    #[serde(default)]
    pub drop_cooldown_secs: u64,
    pub shard_reward: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemConfig {
    #[serde(default)]
    pub limit_mode: String,
    pub max_coins: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardConfig {
    pub enabled: bool,
    #[serde(default)]
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeathProtectConfig {
    pub coins: bool,
    pub shards: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDupeConfig {
    pub scan_interval_seconds: u64,
}

/// Von einem Game-Plugin hochgeladene Konfiguration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameConfig {
    pub game_id: String,
    /// Unix-Timestamp des Uploads.
    pub uploaded_at: i64,
    /// Public-Key-Hex des Uploaders (Game-Server).
    pub uploaded_by: String,
    /// Software-Version des Plugins (optional, für Traceability).
    #[serde(default)]
    pub plugin_version: String,
    /// Drop-Konfiguration für Block-Mining.
    #[serde(default)]
    pub drops: Option<DropTierConfig>,
    /// Mob-Kill Drop-Konfiguration.
    #[serde(default)]
    pub mobs: Option<DropTierConfig>,
    /// Rare-Block Konfiguration.
    #[serde(default)]
    pub rare_block: Option<RareBlockConfig>,
    /// Redeem-Limits.
    #[serde(default)]
    pub redeem: Option<RedeemConfig>,
    /// Scoreboard.
    #[serde(default)]
    pub scoreboard: Option<ScoreboardConfig>,
    /// Death-Protection Toggles.
    #[serde(default)]
    pub death_protect: Option<DeathProtectConfig>,
    /// Anti-Dupe Scanner.
    #[serde(default)]
    pub anti_dupe: Option<AntiDupeConfig>,
}

fn configs_dir() -> PathBuf {
    let mut p = PathBuf::from(data_dir());
    p.push("game_configs");
    p
}

fn config_file(game_id: &str) -> PathBuf {
    let safe: String = game_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let mut p = configs_dir();
    p.push(format!("{safe}.json"));
    p
}

fn history_file(game_id: &str) -> PathBuf {
    let safe: String = game_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let mut p = configs_dir();
    p.push(format!("{safe}_history.json"));
    p
}

/// Validiert die Basis-Struktur einer GameConfig.
/// Manipulationen werden erkannt durch Plausibilitäts-Checks.
pub fn validate_config(cfg: &GameConfig) -> Result<(), String> {
    if cfg.game_id.len() < 3 || cfg.game_id.len() > 64 {
        return Err("game_id: 3-64 Zeichen erforderlich".into());
    }
    if cfg.game_id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-') {
        return Err("game_id: nur a-z, 0-9, _ und - erlaubt".into());
    }

    // Drop-Chance validieren (0.0 - 1.0)
    if let Some(ref drops) = cfg.drops {
        if drops.chance < 0.0 || drops.chance > 1.0 {
            return Err("drops.chance: muss zwischen 0.0 und 1.0 liegen".into());
        }
        if drops.player_cooldown_secs > 3600 {
            return Err("drops.player_cooldown_secs: max. 3600 (1h)".into());
        }
        for (tier, shards) in &drops.tiers {
            if *shards > 1024 {
                return Err(format!("drops.tiers.{}: max. 1024 Shards", tier));
            }
        }
    }

    if let Some(ref mobs) = cfg.mobs {
        if mobs.chance < 0.0 || mobs.chance > 1.0 {
            return Err("mobs.chance: muss zwischen 0.0 und 1.0 liegen".into());
        }
        for (mob, shards) in &mobs.tiers {
            if *shards > 2048 {
                return Err(format!("mobs.tiers.{}: max. 2048 Shards", mob));
            }
        }
    }

    if let Some(ref rb) = cfg.rare_block {
        if rb.find_chance < 0.0 || rb.find_chance > 0.1 {
            return Err("rare_block.find_chance: muss zwischen 0.0 und 0.1 liegen".into());
        }
        if rb.shard_reward > 1024 {
            return Err("rare_block.shard_reward: max. 1024".into());
        }
    }

    if let Some(ref redeem) = cfg.redeem {
        if redeem.max_coins < 0.0 || redeem.max_coins > 10000.0 {
            return Err("redeem.max_coins: muss zwischen 0 und 10000 liegen".into());
        }
    }

    Ok(())
}

/// Speichert die aktuelle Game-Konfiguration und archiviert die vorherige.
pub fn save_config(cfg: &GameConfig) -> Result<(), String> {
    fs::create_dir_all(configs_dir()).map_err(|e| format!("mkdir: {e}"))?;

    let path = config_file(&cfg.game_id);
    let hist_path = history_file(&cfg.game_id);

    // Vorherige Config in History sichern
    if path.exists() {
        if let Ok(prev_bytes) = fs::read(&path) {
            if let Ok(prev) = serde_json::from_slice::<GameConfig>(&prev_bytes) {
                let mut history: Vec<GameConfig> = if hist_path.exists() {
                    fs::read(&hist_path)
                        .ok()
                        .and_then(|b| serde_json::from_slice(&b).ok())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                history.push(prev);
                history.truncate(MAX_HISTORY);
                let hist_json = serde_json::to_vec_pretty(&history)
                    .map_err(|e| format!("history json: {e}"))?;
                fs::write(&hist_path, &hist_json)
                    .map_err(|e| format!("history write: {e}"))?;
            }
        }
    }

    // Aktuelle Config speichern
    let json = serde_json::to_vec_pretty(cfg)
        .map_err(|e| format!("json serialize: {e}"))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &json).map_err(|e| format!("write tmp: {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))?;

    Ok(())
}

/// Lädt die aktuelle Game-Konfiguration.
pub fn load_config(game_id: &str) -> Option<GameConfig> {
    let path = config_file(game_id);
    if !path.exists() {
        return None;
    }
    fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// Lädt die Config-Historie (letzte MAX_HISTORY Einträge).
pub fn load_config_history(game_id: &str) -> Vec<GameConfig> {
    let hist_path = history_file(game_id);
    if !hist_path.exists() {
        return Vec::new();
    }
    fs::read(&hist_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Prüft, ob eine Konfiguration existiert und nicht älter als
/// `max_age_secs` ist. Gibt `None` zurück wenn abgelaufen oder nicht vorhanden.
pub fn is_config_fresh(game_id: &str, max_age_secs: i64) -> bool {
    if let Some(cfg) = load_config(game_id) {
        let now = chrono::Utc::now().timestamp();
        (now - cfg.uploaded_at).abs() < max_age_secs
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_config() {
        let cfg = GameConfig {
            game_id: "mc-pop-test".into(),
            uploaded_at: 1717000000,
            uploaded_by: "a".repeat(64),
            plugin_version: "1.0.0".into(),
            drops: Some(DropTierConfig {
                chance: 0.10,
                player_cooldown_secs: 5,
                tiers: {
                    let mut m = HashMap::new();
                    m.insert("STONE".into(), 1);
                    m.insert("DIAMOND_ORE".into(), 8);
                    m
                },
            }),
            mobs: None,
            rare_block: None,
            redeem: None,
            scoreboard: None,
            death_protect: None,
            anti_dupe: None,
        };
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn test_reject_invalid_chance() {
        let cfg = GameConfig {
            game_id: "test123".into(),
            uploaded_at: 1717000000,
            uploaded_by: "a".repeat(64),
            plugin_version: "1.0.0".into(),
            drops: Some(DropTierConfig {
                chance: 1.5, // > 1.0
                player_cooldown_secs: 5,
                tiers: HashMap::new(),
            }),
            mobs: None,
            rare_block: None,
            redeem: None,
            scoreboard: None,
            death_protect: None,
            anti_dupe: None,
        };
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn test_reject_invalid_game_id() {
        let cfg = GameConfig {
            game_id: "ab".into(), // zu kurz
            uploaded_at: 1717000000,
            uploaded_by: "a".repeat(64),
            plugin_version: "1.0.0".into(),
            drops: None,
            mobs: None,
            rare_block: None,
            redeem: None,
            scoreboard: None,
            death_protect: None,
            anti_dupe: None,
        };
        assert!(validate_config(&cfg).is_err());
    }
}