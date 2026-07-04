//! Node Configuration Database (node_config.db)
//!
//! Ersetzt node_config.json durch eine SQLite-Datenbank mit SQLCipher-Verschlüsselung.
//! Diese Datenbank wird NICHT mit anderen Nodes synchronisiert – sie enthält
//! ausschliesslich lokale Konfigurationswerte.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS config (
//!     key   TEXT PRIMARY KEY,
//!     value TEXT NOT NULL,
//!     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
//! );
//!
//! CREATE TABLE IF NOT EXISTS bootstrap_nodes (
//!     id      INTEGER PRIMARY KEY AUTOINCREMENT,
//!     url     TEXT NOT NULL UNIQUE,
//!     network TEXT NOT NULL DEFAULT 'mainnet'
//! );
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use stone::node_config_db::NodeConfigDB;
//!
//! let db = NodeConfigDB::open(&data_dir)?;
//! db.set("http_port", "3180")?;
//! let port: u16 = db.get_u16("http_port").unwrap_or(3180);
//! ```

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Encryption key derived from hostname (since this is local-only, not synced).
/// Falls die Hostname-Ermittlung fehlschlägt, wird ein fester Fallback verwendet.
fn derive_db_key() -> String {
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "stone-local-node".into());

    // Simple SHA-256 deriven, hex-enkodiert → 64 Zeichen Hex-Key für SQLCipher
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"stone-node-config-v1:");
    hasher.update(host.as_bytes());
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Schlüssel für SQLCipher: raw key (nicht Passphrase).
/// SQLCipher erwartet entweder eine Passphrase via `PRAGMA key` oder einen
/// raw key via `PRAGMA key = "x'...'"`. Wir verwenden raw key (Hex-encoded 256-bit).
fn pragma_key() -> String {
    format!("x'{}'", derive_db_key())
}

/// Lokale Node-Konfigurationsdatenbank.
///
/// Thread-safe via internem Mutex. Wird beim ersten Öffnen automatisch
/// initialisiert (Tabellen anlegen, Migration von node_config.json).
pub struct NodeConfigDB {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl NodeConfigDB {
    /// Öffnet (oder erstellt) die Konfigurationsdatenbank im angegebenen Verzeichnis.
    ///
    /// Der Pfad `data_dir` ist das Verzeichnis, in dem `node_config.db` abgelegt wird.
    /// Falls noch `node_config.json` existiert, werden die Werte automatisch migriert.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("Verzeichnis erstellen: {e}"))?;

        let db_path = data_dir.join("node_config.db");
        let exists = db_path.exists();

        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Datenbank öffnen: {e}"))?;

        // SQLCipher: Verschlüsselung aktivieren
        conn.execute_batch(&format!(
            "PRAGMA key = {key}; PRAGMA cipher_page_size = 4096; PRAGMA kdf_iter = 256000; PRAGMA cipher_hmac_algorithm = HMAC_SHA512; PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;",
            key = pragma_key(),
        ))
        .map_err(|e| format!("SQLCipher-Key setzen: {e}"))?;

        // Tabellen anlegen (falls nicht vorhanden)
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
        .map_err(|e| format!("Schema anlegen: {e}"))?;

        let db = NodeConfigDB {
            conn: Mutex::new(conn),
            db_path,
        };

        // Migration von node_config.json → node_config.db (einmalig)
        if !exists {
            db.migrate_from_json(data_dir);
        }

        Ok(db)
    }

    /// Öffnet die DB im selben Verzeichnis wie die Binary (current working directory).
    pub fn open_default() -> Result<Self, String> {
        Self::open(Path::new("."))
    }

    /// Pfad zur Datenbank-Datei.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    // ── Generic Key-Value ──────────────────────────────────────────────────

    /// Setzt einen String-Wert.
    pub fn set(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock: {e}"))?;
        conn.execute(
            "INSERT INTO config (key, value, updated_at) VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value],
        )
        .map_err(|e| format!("set({key}): {e}"))?;
        Ok(())
    }

    /// Liest einen String-Wert. `None` wenn Key nicht existiert.
    pub fn get(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Löscht einen Key.
    pub fn remove(&self, key: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock: {e}"))?;
        conn.execute("DELETE FROM config WHERE key = ?1", params![key])
            .map_err(|e| format!("remove({key}): {e}"))?;
        Ok(())
    }

    /// Prüft ob ein Key existiert.
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    // ── Typed Getters/Setters ──────────────────────────────────────────────

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn set_bool(&self, key: &str, value: bool) -> Result<(), String> {
        self.set(key, if value { "true" } else { "false" })
    }

    pub fn get_u16(&self, key: &str) -> Option<u16> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn set_u16(&self, key: &str, value: u16) -> Result<(), String> {
        self.set(key, &value.to_string())
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn set_u64(&self, key: &str, value: u64) -> Result<(), String> {
        self.set(key, &value.to_string())
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn set_f64(&self, key: &str, value: f64) -> Result<(), String> {
        self.set(key, &value.to_string())
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn set_u32(&self, key: &str, value: u32) -> Result<(), String> {
        self.set(key, &value.to_string())
    }

    // ── Spezifische Config-Felder ──────────────────────────────────────────

    /// setup_complete: Setup-Wizard abgeschlossen?
    pub fn setup_complete(&self) -> bool {
        self.get_bool("setup_complete").unwrap_or(false)
    }

    pub fn set_setup_complete(&self, v: bool) -> Result<(), String> {
        self.set_bool("setup_complete", v)
    }

    /// node_name: Anzeigename des Nodes
    pub fn node_name(&self) -> String {
        self.get("node_name").unwrap_or_default()
    }

    pub fn set_node_name(&self, v: &str) -> Result<(), String> {
        self.set("node_name", v)
    }

    /// http_port: HTTP API Port (Default: 3180 Mainnet, 3080 Testnet)
    pub fn http_port(&self) -> u16 {
        self.get_u16("http_port").unwrap_or(3180)
    }

    pub fn set_http_port(&self, v: u16) -> Result<(), String> {
        self.set_u16("http_port", v)
    }

    /// p2p_port: libp2p Port (Default: 5003 Mainnet, 4001 Testnet)
    pub fn p2p_port(&self) -> u16 {
        self.get_u16("p2p_port").unwrap_or(5003)
    }

    pub fn set_p2p_port(&self, v: u16) -> Result<(), String> {
        self.set_u16("p2p_port", v)
    }

    /// api_key: Node-API-Key
    pub fn api_key(&self) -> String {
        self.get("api_key").unwrap_or_default()
    }

    pub fn set_api_key(&self, v: &str) -> Result<(), String> {
        self.set("api_key", v)
    }

    /// password_hash: Admin-Passwort-Hash
    pub fn password_hash(&self) -> String {
        self.get("password_hash").unwrap_or_default()
    }

    pub fn set_password_hash(&self, v: &str) -> Result<(), String> {
        self.set("password_hash", v)
    }

    /// wallet_address: Eigene Wallet-Adresse
    pub fn wallet_address(&self) -> String {
        self.get("wallet_address").unwrap_or_default()
    }

    pub fn set_wallet_address(&self, v: &str) -> Result<(), String> {
        self.set("wallet_address", v)
    }

    /// network: "mainnet" | "testnet"
    pub fn network(&self) -> String {
        self.get("network").unwrap_or_else(|| "mainnet".into())
    }

    pub fn set_network(&self, v: &str) -> Result<(), String> {
        self.set("network", v)
    }

    pub fn is_mainnet(&self) -> bool {
        self.network() == "mainnet"
    }

    /// auto_mining_enabled
    pub fn auto_mining_enabled(&self) -> bool {
        self.get_bool("auto_mining_enabled").unwrap_or(false)
    }

    pub fn set_auto_mining_enabled(&self, v: bool) -> Result<(), String> {
        self.set_bool("auto_mining_enabled", v)
    }

    /// auto_mining_timeout_secs
    pub fn auto_mining_timeout_secs(&self) -> u64 {
        self.get_u64("auto_mining_timeout_secs").unwrap_or(120)
    }

    pub fn set_auto_mining_timeout_secs(&self, v: u64) -> Result<(), String> {
        self.set_u64("auto_mining_timeout_secs", v)
    }

    /// miner_heartbeat_timeout_secs
    pub fn miner_heartbeat_timeout_secs(&self) -> u64 {
        self.get_u64("miner_heartbeat_timeout_secs").unwrap_or(30)
    }

    pub fn set_miner_heartbeat_timeout_secs(&self, v: u64) -> Result<(), String> {
        self.set_u64("miner_heartbeat_timeout_secs", v)
    }

    /// miner_heartbeat_partial_delta
    pub fn miner_heartbeat_partial_delta(&self) -> u32 {
        self.get_u32("miner_heartbeat_partial_delta").unwrap_or(6)
    }

    pub fn set_miner_heartbeat_partial_delta(&self, v: u32) -> Result<(), String> {
        self.set_u32("miner_heartbeat_partial_delta", v)
    }

    /// data_dir: Datenverzeichnis
    pub fn data_dir(&self) -> String {
        self.get("data_dir").unwrap_or_else(|| "./stone_data".into())
    }

    pub fn set_data_dir(&self, v: &str) -> Result<(), String> {
        self.set("data_dir", v)
    }

    /// storage_offered_gb
    pub fn storage_offered_gb(&self) -> u64 {
        self.get_u64("storage_offered_gb").unwrap_or(0)
    }

    pub fn set_storage_offered_gb(&self, v: u64) -> Result<(), String> {
        self.set_u64("storage_offered_gb", v)
    }

    /// reward_per_day
    pub fn reward_per_day(&self) -> f64 {
        self.get_f64("reward_per_day").unwrap_or(0.0)
    }

    pub fn set_reward_per_day(&self, v: f64) -> Result<(), String> {
        self.set_f64("reward_per_day", v)
    }

    /// public_ip
    pub fn public_ip(&self) -> String {
        self.get("public_ip").unwrap_or_default()
    }

    pub fn set_public_ip(&self, v: &str) -> Result<(), String> {
        self.set("public_ip", v)
    }

    /// wallet_balance
    pub fn wallet_balance(&self) -> f64 {
        self.get_f64("wallet_balance").unwrap_or(0.0)
    }

    pub fn set_wallet_balance(&self, v: f64) -> Result<(), String> {
        self.set_f64("wallet_balance", v)
    }

    /// mnemonic_once: Einmalige Mnemonic (wird nach erstem Login gelöscht)
    pub fn mnemonic_once(&self) -> String {
        self.get("mnemonic_once").unwrap_or_default()
    }

    pub fn set_mnemonic_once(&self, v: &str) -> Result<(), String> {
        self.set("mnemonic_once", v)
    }

    /// created_at: Erstellungszeitpunkt
    pub fn created_at(&self) -> String {
        self.get("created_at").unwrap_or_default()
    }

    pub fn set_created_at(&self, v: &str) -> Result<(), String> {
        self.set("created_at", v)
    }

    // ── Bootstrap Nodes ────────────────────────────────────────────────────

    /// Fügt eine Bootstrap-Node-URL hinzu.
    pub fn add_bootstrap_node(&self, url: &str, network: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock: {e}"))?;
        conn.execute(
            "INSERT OR IGNORE INTO bootstrap_nodes (url, network) VALUES (?1, ?2)",
            params![url, network],
        )
        .map_err(|e| format!("bootstrap add: {e}"))?;
        Ok(())
    }

    /// Gibt alle Bootstrap-URLs für das angegebene Netzwerk zurück.
    pub fn bootstrap_nodes(&self, network: &str) -> Vec<String> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut stmt = conn
            .prepare("SELECT url FROM bootstrap_nodes WHERE network = ?1 ORDER BY id")
            .ok();
        stmt.as_mut()
            .map(|s| {
                s.query_map(params![network], |row| row.get(0))
                    .ok()
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Gibt ALLE Bootstrap-URLs zurück (für Fallback).
    pub fn all_bootstrap_nodes(&self) -> Vec<String> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut stmt = conn
            .prepare("SELECT url FROM bootstrap_nodes ORDER BY id")
            .ok();
        stmt.as_mut()
            .map(|s| {
                s.query_map([], |row| row.get(0))
                    .ok()
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Entfernt alle Bootstrap-Nodes für ein Netzwerk und setzt neue.
    pub fn replace_bootstrap_nodes(&self, nodes: &[String], network: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock: {e}"))?;
        conn.execute(
            "DELETE FROM bootstrap_nodes WHERE network = ?1",
            params![network],
        )
        .map_err(|e| format!("bootstrap delete: {e}"))?;
        for url in nodes {
            conn.execute(
                "INSERT INTO bootstrap_nodes (url, network) VALUES (?1, ?2)",
                params![url, network],
            )
            .map_err(|e| format!("bootstrap insert: {e}"))?;
        }
        Ok(())
    }

    /// Entfernt eine einzelne Bootstrap-Node-URL.
    pub fn remove_bootstrap_node(&self, url: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock: {e}"))?;
        conn.execute(
            "DELETE FROM bootstrap_nodes WHERE url = ?1",
            params![url],
        )
        .map_err(|e| format!("bootstrap remove: {e}"))?;
        Ok(())
    }

    // ── Seed Peers (als Komma-separierter String) ──────────────────────────

    /// Seed Peers als Vec<String> (zurückkompatibel mit node_config.json)
    pub fn seed_peers(&self) -> Vec<String> {
        // Lese seed_peers als JSON-Array-String oder komma-separiert
        self.get("seed_peers")
            .map(|v| {
                if v.trim().starts_with('[') {
                    serde_json::from_str::<Vec<String>>(&v).unwrap_or_default()
                } else {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }
            })
            .unwrap_or_default()
    }

    pub fn set_seed_peers(&self, peers: &[String]) -> Result<(), String> {
        let json = serde_json::to_string(peers).map_err(|e| format!("seed_peers serialize: {e}"))?;
        self.set("seed_peers", &json)
    }

    // ── Migration ──────────────────────────────────────────────────────────

    /// Migriert Werte aus einer existierenden node_config.json in die Datenbank.
    /// Führt kein Delete der JSON-Datei durch (Sicherheit).
    fn migrate_from_json(&self, data_dir: &Path) {
        let json_path = data_dir.join("node_config.json");
        if !json_path.exists() {
            return;
        }

        let data = match std::fs::read_to_string(&json_path) {
            Ok(d) => d,
            Err(_) => return,
        };

        let val: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return,
        };

        let obj = match val.as_object() {
            Some(o) => o,
            None => return,
        };

        let mut migrated = 0u32;
        for (key, value) in obj {
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Array(arr) => serde_json::to_string(arr).unwrap_or_default(),
                _ => continue,
            };

            // Bootstrap-Nodes separat behandeln
            if key == "seed_peers" {
                if let serde_json::Value::Array(arr) = value {
                    for url in arr {
                        if let Some(u) = url.as_str() {
                            let net = if u.contains(":4001") || u.contains(":3080") {
                                "testnet"
                            } else {
                                "mainnet"
                            };
                            let _ = self.add_bootstrap_node(u, net);
                        }
                    }
                }
                // seed_peers auch als config-key speichern (für Rückkompatibilität)
                let json = serde_json::to_string(value).unwrap_or_default();
                if let Err(e) = self.set(key, &json) {
                    eprintln!("[config-db] Migration {key}: {e}");
                    continue;
                }
            } else {
                if let Err(e) = self.set(key, &value_str) {
                    eprintln!("[config-db] Migration {key}: {e}");
                    continue;
                }
            }
            migrated += 1;
        }

        if migrated > 0 {
            println!(
                "[config-db] ✓ {migrated} Keys aus {} migriert → {}",
                json_path.display(),
                self.db_path.display(),
            );
        }
    }
}

impl std::fmt::Debug for NodeConfigDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfigDB")
            .field("path", &self.db_path)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn test_db() -> (NodeConfigDB, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let db = NodeConfigDB::open(dir.path()).expect("open");
        (db, dir)
    }

    #[test]
    fn test_basic_set_get() {
        let (db, _dir) = test_db();
        db.set("test_key", "hello").unwrap();
        assert_eq!(db.get("test_key").as_deref(), Some("hello"));
    }

    #[test]
    fn test_typed_getters() {
        let (db, _dir) = test_db();
        db.set_u16("port", 3180).unwrap();
        db.set_bool("enabled", true).unwrap();
        db.set_u64("timeout", 120).unwrap();

        assert_eq!(db.get_u16("port"), Some(3180));
        assert_eq!(db.get_bool("enabled"), Some(true));
        assert_eq!(db.get_u64("timeout"), Some(120));
    }

    #[test]
    fn test_defaults() {
        let (db, _dir) = test_db();
        assert_eq!(db.http_port(), 3180);
        assert_eq!(db.network(), "mainnet");
        assert!(!db.auto_mining_enabled());
    }

    #[test]
    fn test_bootstrap_nodes() {
        let (db, _dir) = test_db();
        db.add_bootstrap_node("http://1.2.3.4:3180", "mainnet").unwrap();
        db.add_bootstrap_node("http://5.6.7.8:3080", "testnet").unwrap();

        assert_eq!(db.bootstrap_nodes("mainnet").len(), 1);
        assert_eq!(db.bootstrap_nodes("testnet").len(), 1);
        assert_eq!(db.all_bootstrap_nodes().len(), 2);
    }

    #[test]
    fn test_network_switch() {
        let (db, _dir) = test_db();
        assert_eq!(db.network(), "mainnet");
        assert!(db.is_mainnet());

        db.set_network("testnet").unwrap();
        assert_eq!(db.network(), "testnet");
        assert!(!db.is_mainnet());
    }
}
