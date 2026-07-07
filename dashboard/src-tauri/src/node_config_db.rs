//! Node Configuration Database (dashboard-side)
//!
//! Mini-Wrapper für rusqlite/sqlcipher. Basiert auf dem gleichen Schema wie
//! stone::node_config_db, aber als eigenständige Implementierung für die Tauri-App.
//! Wird verwendet um node_config.db zu lesen/schreiben, die der stone-node
//! Kindprozess beim Start einliest.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Leitet den SQLCipher-Schlüssel aus dem Hostname ab (identisch zu stone::node_config_db).
fn derive_db_key() -> String {
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "stone-local-node".into());

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"stone-node-config-v1:");
    hasher.update(host.as_bytes());
    hex::encode(hasher.finalize())
}

pub struct NodeConfigDB {
    conn: Mutex<Connection>,
    _db_path: PathBuf,
}

impl NodeConfigDB {
    /// Öffnet (oder erstellt) die Konfigurationsdatenbank im angegebenen Verzeichnis.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("mkdir: {e}"))?;

        let db_path = data_dir.join("node_config.db");
        let conn = Connection::open(&db_path).map_err(|e| format!("open db: {e}"))?;

        let key_hex = derive_db_key();
        conn.execute_batch(&format!(
            "PRAGMA key = \"x'{key_hex}'\"; PRAGMA cipher_page_size = 4096;"
        ))
        .map_err(|e| format!("pragma key: {e}"))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS config (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS bootstrap_nodes (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                url     TEXT NOT NULL UNIQUE,
                network TEXT NOT NULL DEFAULT 'mainnet'
            );"
        )
        .map_err(|e| format!("schema: {e}"))?;

        Ok(NodeConfigDB {
            conn: Mutex::new(conn),
            _db_path: db_path,
        })
    }

    pub fn set(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("lock: {e}"))?;
        conn.execute(
            "INSERT INTO config (key, value, updated_at) VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value],
        ).map_err(|e| format!("set {key}: {e}"))?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        conn.query_row("SELECT value FROM config WHERE key = ?1", params![key], |row| row.get(0))
            .optional().ok().flatten()
    }

    pub fn set_u16(&self, key: &str, v: u16) -> Result<(), String> {
        self.set(key, &v.to_string())
    }

    // ── Bootstrap Nodes ──────────────────────────────────────────────────


    pub fn replace_bootstrap_nodes(&self, nodes: &[String], network: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("lock: {e}"))?;
        conn.execute("DELETE FROM bootstrap_nodes WHERE network = ?1", params![network])
            .map_err(|e| format!("bootstrap del: {e}"))?;
        for url in nodes {
            conn.execute(
                "INSERT INTO bootstrap_nodes (url, network) VALUES (?1, ?2)",
                params![url, network],
            ).map_err(|e| format!("bootstrap ins: {e}"))?;
        }
        Ok(())
    }

    /// Migriert alle relevanten Keys aus node_config.json (falls vorhanden).
    pub fn migrate_json_if_needed(&self, data_dir: &Path) {
        let json_path = data_dir.join("node_config.json");
        if !json_path.exists() { return; }

        let data = match std::fs::read_to_string(&json_path) {
            Ok(d) => d, Err(_) => return,
        };
        let val: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v, Err(_) => return,
        };
        let obj = match val.as_object() {
            Some(o) => o, None => return,
        };

        let string_keys = &[
            "setup_complete", "password_hash", "node_name", "wallet_address",
            "mnemonic_once", "api_key", "created_at", "data_dir", "public_ip",
            "network", "auto_mining_enabled", "auto_mining_timeout_secs",
            "miner_heartbeat_timeout_secs", "miner_heartbeat_partial_delta",
            "storage_offered_gb", "reward_per_day", "wallet_balance",
            "http_port", "p2p_port",
        ];

        for key in string_keys {
            if self.get(key).is_some() { continue; } // bereits in DB
            if let Some(value) = obj.get(*key) {
                let v = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                let _ = self.set(key, &v);
            }
        }

        // seed_peers
        if self.get("seed_peers").is_none() {
            if let Some(peers) = obj.get("seed_peers").and_then(|v| v.as_array()) {
                let urls: Vec<String> = peers.iter()
                    .filter_map(|p| p.as_str().map(|s| s.to_string()))
                    .collect();
                if !urls.is_empty() {
                    let json = serde_json::to_string(&urls).unwrap_or_default();
                    let _ = self.set("seed_peers", &json);
                }
            }
        }
    }
}
