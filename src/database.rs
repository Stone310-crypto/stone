//! SQLite-basierte persistenz für StoneChain — ersetzt JSON-Dateien.
//!
//! ## Tabellen
//!
//! | Tabelle             | Ersetzt                          |
//! |---------------------|----------------------------------|
//! | `users`             | `stone_data/users.json`         |
//! | `organizations`     | `stone_data/organizations.json` |
//! | `message_pool`      | `stone_data/message_pool/`      |
//! | `peers`             | `stone_data/peers.json`         |
//! | `trust_registry`    | `stone_data/trust.json`         |
//! | `game_economy`      | `stone_data/game_economy.json`  |
//! | `db_metadata`       | Lokale Metadaten (Sync-Basis)   |
//!
//! ## Synchronisations-Logik (wie bei Bitcoin)
//!
//! 1. Längste DB (meiste Einträge) gewinnt
//! 2. Bei Gleichstand: Ältester Eintrag gewinnt
//! 3. Bei absolutem Gleichstand: Keine Änderung

use std::sync::{Arc, Mutex, OnceLock};

use chrono::Utc;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::blockchain::data_dir;

/// Globaler Datenbank-Pointer — wird beim Server-Start gesetzt.
/// Alle Persistenz-Funktionen (`save_users`, `save_orgs`, etc.) schreiben
/// automatisch parallel in diese DB, wenn sie gesetzt ist.
static GLOBAL_DB: OnceLock<Database> = OnceLock::new();

/// Setzt die globale Datenbank-Instanz. Wird einmal beim Server-Start aufgerufen.
pub fn set_global_db(db: Database) {
    let _ = GLOBAL_DB.set(db);
}

/// Gibt die globale Datenbank zurück, falls sie bereits initialisiert wurde.
pub fn global_db() -> Option<&'static Database> {
    GLOBAL_DB.get()
}

/// Marker-Key für einmalige JSON→SQLite Migration.
const MIGRATION_DONE_KEY: &str = "__mig_json_to_sqlite_v1";

// ─── DbMetadata ────────────────────────────────────────────────────────────────

/// Datenbank-Metadaten für Netzwerk-Synchronisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMetadata {
    pub table_count: u64,
    pub oldest_entry: u64,
    pub newest_entry: u64,
    pub node_id: String,
}

impl DbMetadata {
    /// Erzeugt Metadaten aus der lokalen DB.
    pub fn from_db(db: &Database, node_id: &str) -> Result<Self, rusqlite::Error> {
        let conn = db.conn.lock().unwrap_or_else(|e| e.into_inner());

        let user_count: u64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap_or(0);
        let org_count: u64 = conn.query_row("SELECT COUNT(*) FROM organizations", [], |r| r.get(0)).unwrap_or(0);
        let msg_count: u64 = conn.query_row("SELECT COUNT(*) FROM message_pool", [], |r| r.get(0)).unwrap_or(0);
        let peer_count: u64 = conn.query_row("SELECT COUNT(*) FROM peers", [], |r| r.get(0)).unwrap_or(0);
        let trust_count: u64 = conn.query_row("SELECT COUNT(*) FROM trust_registry", [], |r| r.get(0)).unwrap_or(0);
        let game_count: u64 = conn.query_row("SELECT COUNT(*) FROM game_economy", [], |r| r.get(0)).unwrap_or(0);
        let table_count = user_count + org_count + msg_count + peer_count + trust_count + game_count;

        let mut oldest = u64::MAX;
        for (table, ts_col) in &[
            ("users", "created_at"),
            ("organizations", "created_at"),
            ("message_pool", "timestamp"),
            ("peers", "created_at"),
            ("trust_registry", "created_at"),
        ] {
            if let Ok(val) = conn.query_row(
                &format!("SELECT MIN({ts_col}) FROM {table} WHERE {ts_col} > 0"),
                [], |r| r.get::<_, i64>(0),
            ) {
                if val > 0 && (val as u64) < oldest {
                    oldest = val as u64;
                }
            }
        }
        if oldest == u64::MAX { oldest = 0; }

        let mut newest = 0u64;
        for (table, ts_col) in &[
            ("users", "created_at"),
            ("organizations", "created_at"),
            ("message_pool", "timestamp"),
            ("peers", "created_at"),
            ("trust_registry", "created_at"),
        ] {
            if let Ok(val) = conn.query_row(
                &format!("SELECT MAX({ts_col}) FROM {table} WHERE {ts_col} > 0"),
                [], |r| r.get::<_, i64>(0),
            ) {
                if (val as u64) > newest { newest = val as u64; }
            }
        }

        Ok(DbMetadata { table_count, oldest_entry: oldest, newest_entry: newest, node_id: node_id.to_string() })
    }
}

// ─── Database ──────────────────────────────────────────────────────────────────

/// Clonable — mehrere Referenzen teilen sich dieselbe Connection.
#[derive(Clone)]
pub struct Database {
    pub conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open() -> Result<Self, rusqlite::Error> {
        let dir = data_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = format!("{dir}/stone.db");
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;"
        )?;
        let db = Database { conn: Arc::new(Mutex::new(conn)) };
        db.run_migrations()?;
        // Idempotent: Füge bio + updated_at Spalten hinzu (wird nur beim ersten Start aktiv)
        let _ = db.add_profile_columns();
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let db = Database { conn: Arc::new(Mutex::new(conn)) };
        db.run_migrations()?;
        let _ = db.add_profile_columns();
        Ok(db)
    }

    /// Einmalige JSON→SQLite Migration.
    pub fn migrate_from_json_files(&self) {
        if self.get_meta(MIGRATION_DONE_KEY).is_some() {
            return;
        }

        let dir = data_dir();
        let mut total: u64 = 0;

        // ── users.json → users ──────────────────────────────────────
        let users_path = format!("{dir}/users.json");
        if std::path::Path::new(&users_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&users_path) {
                if let Ok(users) = serde_json::from_str::<Vec<crate::auth::User>>(&raw) {
                    let count = users.len();
                    if let Err(e) = self.save_users(&users) {
                        eprintln!("[db] ⚠️  users.json Migration fehlgeschlagen: {e}");
                    } else {
                        println!("[db] ✅ {count} User aus users.json migriert");
                        total += count as u64;
                    }
                }
            }
        }

        // ── organizations.json → organizations ─────────────────────
        let orgs_path = format!("{dir}/organizations.json");
        if std::path::Path::new(&orgs_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&orgs_path) {
                if let Ok(orgs) = serde_json::from_str::<Vec<crate::organization::Organization>>(&raw) {
                    let count = orgs.len();
                    if let Err(e) = self.save_organizations(&orgs) {
                        eprintln!("[db] ⚠️  organizations.json Migration fehlgeschlagen: {e}");
                    } else {
                        println!("[db] ✅ {count} Organisationen aus organizations.json migriert");
                        total += count as u64;
                    }
                }
            }
        }

        // ── peers.json → peers ──────────────────────────────────────
        let peers_path = format!("{dir}/peers.json");
        if std::path::Path::new(&peers_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&peers_path) {
                if let Ok(peers) = serde_json::from_str::<Vec<crate::master::PeerInfo>>(&raw) {
                    let count = peers.len();
                    if let Err(e) = self.save_peers(&peers) {
                        eprintln!("[db] ⚠️  peers.json Migration fehlgeschlagen: {e}");
                    } else {
                        println!("[db] ✅ {count} Peers aus peers.json migriert");
                        total += count as u64;
                    }
                }
            }
        }

        // ── trust.json → trust_registry + trust_history ────────────
        let trust_path = format!("{dir}/trust.json");
        if std::path::Path::new(&trust_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&trust_path) {
                #[derive(serde::Deserialize, Default)]
                struct TrustPersist {
                    #[serde(default)]
                    registry: Vec<crate::master::TrustEntry>,
                    #[serde(default)]
                    history: Vec<crate::master::TrustVote>,
                }
                if let Ok(data) = serde_json::from_str::<TrustPersist>(&raw) {
                    let count_r = data.registry.len();
                    let count_h = data.history.len();
                    if let Err(e) = self.save_trust(&data.registry, &data.history) {
                        eprintln!("[db] ⚠️  trust.json Migration fehlgeschlagen: {e}");
                    } else {
                        println!("[db] ✅ {count_r} Trust-Einträge + {count_h} Votes aus trust.json migriert");
                        total += (count_r + count_h) as u64;
                    }
                }
            }
        }

        // ── game_economy.json → game_economy ──────────────────────
        let ge_path = format!("{dir}/game_economy.json");
        if std::path::Path::new(&ge_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&ge_path) {
                if !raw.trim().is_empty() {
                    if let Err(e) = self.save_game_economy(&raw) {
                        eprintln!("[db] ⚠️  game_economy.json Migration fehlgeschlagen: {e}");
                    } else {
                        println!("[db] ✅ game_economy.json in SQLite migriert");
                        total += 1;
                    }
                }
            }
        }

        // ── message_pool/sequence.json → message_sequence ─────────
        let mp_dir = format!("{dir}/message_pool");
        let seq_path = format!("{mp_dir}/sequence.json");
        if std::path::Path::new(&seq_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&seq_path) {
                if let Ok(seq) = serde_json::from_str::<crate::message_pool::SequenceState>(&raw) {
                    if let Err(e) = self.save_sequence_state(&seq) {
                        eprintln!("[db] ⚠️  sequence.json Migration fehlgeschlagen: {e}");
                    } else {
                        println!("[db] ✅ Sequenzstand aus sequence.json migriert (next={})", seq.next_sequence);
                    }
                }
            }
        }

        // ── message_pool/pending.json → message_pool ──────────────
        let pending_path = format!("{mp_dir}/pending.json");
        if std::path::Path::new(&pending_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&pending_path) {
                if let Ok(msgs) = serde_json::from_str::<Vec<crate::message_pool::PooledMessage>>(&raw) {
                    let count = msgs.len();
                    if let Err(e) = self.save_pool_messages(&msgs) {
                        eprintln!("[db] ⚠️  pending.json Migration fehlgeschlagen: {e}");
                    } else {
                        println!("[db] ✅ {count} Pending Messages aus pending.json migriert");
                        total += count as u64;
                    }
                }
            }
        }

        if let Err(e) = self.set_meta(MIGRATION_DONE_KEY, "1") {
            eprintln!("[db] ⚠️  Migrations-Marker konnte nicht gesetzt werden: {e}");
        } else {
            println!("[db] 🎉 JSON→SQLite Migration abgeschlossen ({total} Einträge insgesamt)");
        }
    }

    fn run_migrations(&self) -> Result<(), rusqlite::Error> {
        let conn_lock = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let conn: &Connection = &*conn_lock;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS db_metadata (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL DEFAULT '',
                wallet_address  TEXT NOT NULL DEFAULT '',
                api_key         TEXT NOT NULL DEFAULT '',
                phrase_hash     TEXT NOT NULL DEFAULT '',
                quota_bytes     INTEGER NOT NULL DEFAULT 1073741824,
                account_type    TEXT NOT NULL DEFAULT 'user',
                org_id          TEXT NOT NULL DEFAULT '',
                org_role        TEXT NOT NULL DEFAULT '',
                discord_id      TEXT NOT NULL DEFAULT '',
                discord_username TEXT NOT NULL DEFAULT '',
                created_at      INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_users_wallet ON users(wallet_address);
            CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);

            CREATE TABLE IF NOT EXISTS organizations (
                id                  TEXT PRIMARY KEY,
                name                TEXT NOT NULL DEFAULT '',
                description         TEXT NOT NULL DEFAULT '',
                owner_id            TEXT NOT NULL DEFAULT '',
                created_at          INTEGER NOT NULL DEFAULT 0,
                chain_hash          TEXT NOT NULL DEFAULT '',
                chain_block_index   INTEGER NOT NULL DEFAULT 0,
                chain_block_hash    TEXT NOT NULL DEFAULT '',
                full_json           TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_orgs_owner ON organizations(owner_id);

            CREATE TABLE IF NOT EXISTS message_pool (
                msg_id            TEXT PRIMARY KEY,
                sequence          INTEGER NOT NULL DEFAULT 0,
                from_wallet       TEXT NOT NULL DEFAULT '',
                to_wallet         TEXT NOT NULL DEFAULT '',
                from_user_id      TEXT NOT NULL DEFAULT '',
                from_name         TEXT NOT NULL DEFAULT '',
                encrypted_content TEXT NOT NULL DEFAULT '',
                nonce             TEXT NOT NULL DEFAULT '',
                timestamp         INTEGER NOT NULL DEFAULT 0,
                signature         TEXT NOT NULL DEFAULT '',
                pow_nonce         INTEGER NOT NULL DEFAULT 0,
                status            TEXT NOT NULL DEFAULT 'Pending',
                status_extra      TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_msg_sequence ON message_pool(sequence);
            CREATE INDEX IF NOT EXISTS idx_msg_from ON message_pool(from_wallet);
            CREATE INDEX IF NOT EXISTS idx_msg_to ON message_pool(to_wallet);
            CREATE INDEX IF NOT EXISTS idx_msg_status ON message_pool(status);

            CREATE TABLE IF NOT EXISTS message_sequence (
                id                 INTEGER PRIMARY KEY CHECK (id = 1),
                next_sequence      INTEGER NOT NULL DEFAULT 1,
                last_confirmed_seq INTEGER NOT NULL DEFAULT 0,
                batch_count        INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO message_sequence (id, next_sequence, last_confirmed_seq, batch_count)
            VALUES (1, 1, 0, 0);

            CREATE TABLE IF NOT EXISTS batch_records (
                merkle_root   TEXT PRIMARY KEY,
                block_index   INTEGER NOT NULL DEFAULT 0,
                entries_json  TEXT NOT NULL DEFAULT '[]',
                messages_json TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS peers (
                url          TEXT PRIMARY KEY,
                name         TEXT NOT NULL DEFAULT '',
                status       TEXT NOT NULL DEFAULT 'Unreachable',
                block_height INTEGER NOT NULL DEFAULT 0,
                last_seen    INTEGER NOT NULL DEFAULT 0,
                last_hash    TEXT NOT NULL DEFAULT '',
                latency_ms   INTEGER NOT NULL DEFAULT 0,
                created_at   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS trust_registry (
                peer_id        TEXT PRIMARY KEY,
                public_key_hex TEXT NOT NULL DEFAULT '',
                name           TEXT NOT NULL DEFAULT '',
                status         TEXT NOT NULL DEFAULT 'Pending',
                votes_approve  TEXT NOT NULL DEFAULT '[]',
                votes_reject   TEXT NOT NULL DEFAULT '[]',
                requested_at   INTEGER NOT NULL DEFAULT 0,
                decided_at     INTEGER,
                created_at     INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS trust_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_peer_id   TEXT NOT NULL,
                target_peer_id  TEXT NOT NULL,
                approve         INTEGER NOT NULL DEFAULT 0,
                timestamp       INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_trust_target ON trust_history(target_peer_id);

            CREATE TABLE IF NOT EXISTS game_economy (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );"
        )?;
        Ok(())
    }

    /// Idempotentes Hinzufügen von bio + updated_at Spalten.
    /// Wird beim ersten Start nach der Migration einmal ausgeführt.
    pub fn add_profile_columns(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // Versuche bio-Spalte hinzuzufügen, ignoriere NUR "duplicate column" Fehler
        for sql in &[
            "ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0",
        ] {
            match conn.execute(sql, []) {
                Ok(_) => println!("[db] ✅ Spalte hinzugefügt: {sql}"),
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("duplicate column") {
                        // Spalte existiert bereits → OK
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    // ─── Metadaten ────────────────────────────────────────────────────
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("INSERT INTO db_metadata (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value])?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT value FROM db_metadata WHERE key = ?1", params![key], |r| r.get(0)).ok()
    }

    // ─── Users ────────────────────────────────────────────────────────
    pub fn save_users(&self, users: &[crate::auth::User]) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now().timestamp();
        for u in users {
            conn.execute(
                "INSERT INTO users (id, name, bio, wallet_address, api_key, phrase_hash, quota_bytes, account_type, org_id, org_role, discord_id, discord_username, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                 ON CONFLICT(id) DO UPDATE SET name=excluded.name, bio=excluded.bio, wallet_address=excluded.wallet_address, api_key=excluded.api_key, phrase_hash=excluded.phrase_hash, quota_bytes=excluded.quota_bytes, account_type=excluded.account_type, org_id=excluded.org_id, org_role=excluded.org_role, discord_id=excluded.discord_id, discord_username=excluded.discord_username, updated_at=excluded.updated_at",
                params![u.id, u.name, u.bio, u.wallet_address, u.api_key, u.phrase_hash, u.quota_bytes as i64, u.account_type, u.org_id, u.org_role, u.discord_id, u.discord_username, now, u.updated_at],
            )?;
        }
        Ok(())
    }

    pub fn load_users(&self) -> Result<Vec<crate::auth::User>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT id, name, wallet_address, api_key, phrase_hash, quota_bytes, account_type, org_id, org_role, discord_id, discord_username, CAST(COALESCE(bio,'') AS TEXT), CAST(COALESCE(updated_at,0) AS INTEGER) FROM users ORDER BY name"
        )?;
        let users = stmt.query_map([], |row| {
            let bio_val: String = row.get(10).unwrap_or_default();
            let ts_val: i64 = row.get(11).unwrap_or_default();
            Ok(crate::auth::User {
                id: row.get(0)?, name: row.get(1)?, wallet_address: row.get(2)?,
                api_key: row.get(3)?, phrase_hash: row.get(4)?,
                quota_bytes: row.get::<_, i64>(5).unwrap_or(0) as u64,
                account_type: row.get(6)?, org_id: row.get(7)?, org_role: row.get(8)?,
                discord_id: row.get(9)?, discord_username: String::new(),
                bio: bio_val,
                updated_at: ts_val,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(users)
    }

    pub fn user_count(&self) -> u64 {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0)).map(|v| v as u64).unwrap_or(0)
    }

    // ─── Organizations ────────────────────────────────────────────────
    pub fn save_organizations(&self, orgs: &[crate::organization::Organization]) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for o in orgs {
            let full_json = serde_json::to_string(o).unwrap_or_else(|_| "{}".into());
            conn.execute(
                "INSERT INTO organizations (id, name, description, owner_id, created_at, chain_hash, chain_block_index, chain_block_hash, full_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, owner_id=excluded.owner_id, chain_hash=excluded.chain_hash, chain_block_index=excluded.chain_block_index, chain_block_hash=excluded.chain_block_hash, full_json=excluded.full_json",
                params![o.id, o.name, o.description, o.owner_id, o.created_at, o.chain_hash, o.chain_block_index as i64, o.chain_block_hash, full_json],
            )?;
        }
        Ok(())
    }

    pub fn load_organizations(&self) -> Result<Vec<crate::organization::Organization>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT full_json FROM organizations ORDER BY name")?;
        let orgs: Vec<crate::organization::Organization> = stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            match serde_json::from_str(&json) {
                Ok(org) => Ok(Some(org)),
                Err(e) => {
                    eprintln!("[db] ⚠️ load_organizations: full_json konnte nicht deserialisiert werden: {e}");
                    Ok(None)
                }
            }
        })?.filter_map(|r| r.ok().flatten()).collect();
        Ok(orgs)
    }

    // ─── Message Pool ─────────────────────────────────────────────────
    pub fn save_pool_messages(&self, messages: &[crate::message_pool::PooledMessage]) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for m in messages {
            let status_str = match &m.status {
                crate::message_pool::MessageStatus::Pending => "Pending",
                crate::message_pool::MessageStatus::Batched { .. } => "Batched",
                crate::message_pool::MessageStatus::Confirmed { .. } => "Confirmed",
            };
            let status_extra = match &m.status {
                crate::message_pool::MessageStatus::Batched { batch_id } => batch_id.clone(),
                crate::message_pool::MessageStatus::Confirmed { block_index } => block_index.to_string(),
                _ => String::new(),
            };
            conn.execute(
                "INSERT INTO message_pool (msg_id, sequence, from_wallet, to_wallet, from_user_id, from_name, encrypted_content, nonce, timestamp, signature, pow_nonce, status, status_extra)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                 ON CONFLICT(msg_id) DO UPDATE SET sequence=excluded.sequence, from_wallet=excluded.from_wallet, to_wallet=excluded.to_wallet, from_user_id=excluded.from_user_id, from_name=excluded.from_name, encrypted_content=excluded.encrypted_content, nonce=excluded.nonce, timestamp=excluded.timestamp, signature=excluded.signature, pow_nonce=excluded.pow_nonce, status=excluded.status, status_extra=excluded.status_extra",
                params![m.msg_id, m.sequence as i64, m.from_wallet, m.to_wallet, m.from_user_id, m.from_name, m.encrypted_content, m.nonce, m.timestamp, m.signature, m.pow_nonce as i64, status_str, status_extra],
            )?;
        }
        Ok(())
    }

    pub fn load_pending_messages(&self) -> Result<Vec<crate::message_pool::PooledMessage>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT msg_id, sequence, from_wallet, to_wallet, from_user_id, from_name, encrypted_content, nonce, timestamp, signature, pow_nonce, status, status_extra
             FROM message_pool WHERE status = 'Pending' ORDER BY sequence"
        )?;
        let msgs = stmt.query_map([], |row| {
            let status_str: String = row.get(11)?;
            let extra: String = row.get(12)?;
            let status = match status_str.as_str() {
                "Batched" => crate::message_pool::MessageStatus::Batched { batch_id: extra },
                "Confirmed" => crate::message_pool::MessageStatus::Confirmed { block_index: extra.parse().unwrap_or(0) },
                _ => crate::message_pool::MessageStatus::Pending,
            };
            Ok(crate::message_pool::PooledMessage {
                msg_id: row.get(0)?, sequence: row.get::<_, i64>(1).unwrap_or(0) as u64,
                from_wallet: row.get(2)?, to_wallet: row.get(3)?, from_user_id: row.get(4)?,
                from_name: row.get(5)?, encrypted_content: row.get(6)?, nonce: row.get(7)?,
                timestamp: row.get(8)?, signature: row.get(9)?,
                pow_nonce: row.get::<_, i64>(10).unwrap_or(0) as u64, status,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(msgs)
    }

    pub fn remove_pool_message(&self, msg_id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM message_pool WHERE msg_id = ?1", params![msg_id])?;
        Ok(())
    }

    // ─── Sequence State ───────────────────────────────────────────────
    pub fn load_sequence_state(&self) -> Result<crate::message_pool::SequenceState, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT next_sequence, last_confirmed_seq, batch_count FROM message_sequence WHERE id = 1", [], |row| {
            Ok(crate::message_pool::SequenceState {
                next_sequence: row.get::<_, i64>(0).unwrap_or(1) as u64,
                last_confirmed_seq: row.get::<_, i64>(1).unwrap_or(0) as u64,
                batch_count: row.get::<_, i64>(2).unwrap_or(0) as u64,
            })
        })
    }

    pub fn save_sequence_state(&self, state: &crate::message_pool::SequenceState) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("UPDATE message_sequence SET next_sequence=?1, last_confirmed_seq=?2, batch_count=?3 WHERE id=1",
            params![state.next_sequence as i64, state.last_confirmed_seq as i64, state.batch_count as i64])?;
        Ok(())
    }

    // ─── Batch Records ────────────────────────────────────────────────
    pub fn save_batch_record(&self, merkle_root: &str, block_index: u64, entries_json: &str, messages_json: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("INSERT INTO batch_records (merkle_root, block_index, entries_json, messages_json) VALUES (?1,?2,?3,?4) ON CONFLICT(merkle_root) DO UPDATE SET block_index=excluded.block_index, entries_json=excluded.entries_json, messages_json=excluded.messages_json",
            params![merkle_root, block_index as i64, entries_json, messages_json])?;
        Ok(())
    }

    pub fn load_batch_record(&self, merkle_root: &str) -> Result<Option<(u64, String, String)>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        match conn.query_row("SELECT block_index, entries_json, messages_json FROM batch_records WHERE merkle_root=?1", params![merkle_root],
            |row| Ok((row.get::<_, i64>(0).unwrap_or(0) as u64, row.get::<_, String>(1).unwrap_or_default(), row.get::<_, String>(2).unwrap_or_default()))
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ─── Peers ───────────────────────────────────────────────────────
    pub fn save_peers(&self, peers: &[crate::master::PeerInfo]) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now().timestamp();
        for p in peers {
            conn.execute(
                "INSERT INTO peers (url, name, status, block_height, last_seen, last_hash, latency_ms, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(url) DO UPDATE SET name=excluded.name, status=excluded.status, block_height=excluded.block_height, last_seen=excluded.last_seen, last_hash=excluded.last_hash, latency_ms=excluded.latency_ms",
                params![p.url, p.name.as_deref().unwrap_or(""), format!("{:?}", p.status), p.block_height as i64, p.last_seen, p.last_hash.as_deref().unwrap_or(""), p.latency_ms.unwrap_or(0) as i64, now],
            )?;
        }
        Ok(())
    }

    pub fn load_peers(&self) -> Result<Vec<crate::master::PeerInfo>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT url, name, status, block_height, last_seen, last_hash, latency_ms FROM peers ORDER BY block_height DESC")?;
        let peers = stmt.query_map([], |row| {
            let url: String = row.get(0)?;
            let name: String = row.get(1)?;
            let status_str: String = row.get(2)?;
            let status = match status_str.as_str() {
                "Healthy" => crate::master::PeerStatus::Healthy,
                "Diverged" => crate::master::PeerStatus::Diverged,
                "Quarantined" => crate::master::PeerStatus::Quarantined,
                _ => crate::master::PeerStatus::Unreachable,
            };
            let mut peer = crate::master::PeerInfo::new(url);
            peer.name = if name.is_empty() { None } else { Some(name) };
            peer.status = status;
            peer.block_height = row.get::<_, i64>(3).unwrap_or(0) as u64;
            peer.last_seen = row.get(4)?;
            let lh: String = row.get(5)?;
            peer.last_hash = if lh.is_empty() { None } else { Some(lh) };
            let lat: i64 = row.get(6)?;
            peer.latency_ms = if lat > 0 { Some(lat as u128) } else { None };
            Ok(peer)
        })?.filter_map(|r| r.ok()).collect();
        Ok(peers)
    }

    // ─── Trust ───────────────────────────────────────────────────────
    pub fn save_trust(&self, registry: &[crate::master::TrustEntry], history: &[crate::master::TrustVote]) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now().timestamp();
        for entry in registry {
            let votes_approve_json = serde_json::to_string(&entry.votes_approve).unwrap_or_else(|_| "[]".into());
            let votes_reject_json = serde_json::to_string(&entry.votes_reject).unwrap_or_else(|_| "[]".into());
            conn.execute(
                "INSERT INTO trust_registry (peer_id, public_key_hex, name, status, votes_approve, votes_reject, requested_at, decided_at, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(peer_id) DO UPDATE SET public_key_hex=excluded.public_key_hex, name=excluded.name, status=excluded.status, votes_approve=excluded.votes_approve, votes_reject=excluded.votes_reject, requested_at=excluded.requested_at, decided_at=excluded.decided_at",
                params![entry.peer_id, entry.public_key_hex, entry.name.as_deref().unwrap_or(""), format!("{:?}", entry.status).to_lowercase(), votes_approve_json, votes_reject_json, entry.requested_at, entry.decided_at, now],
            )?;
        }
        for vote in history {
            conn.execute(
                "INSERT INTO trust_history (voter_peer_id, target_peer_id, approve, timestamp) VALUES (?1,?2,?3,?4)",
                params![vote.voter_peer_id, vote.target_peer_id, if vote.approve { 1 } else { 0 }, vote.timestamp],
            )?;
        }
        Ok(())
    }

    pub fn load_trust_registry(&self) -> Result<Vec<crate::master::TrustEntry>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT peer_id, public_key_hex, name, status, votes_approve, votes_reject, requested_at, decided_at FROM trust_registry"
        )?;
        let entries = stmt.query_map([], |row| {
            let status_str: String = row.get(3)?;
            Ok(crate::master::TrustEntry {
                peer_id: row.get(0)?, public_key_hex: row.get(1)?,
                name: { let n: String = row.get(2)?; if n.is_empty() { None } else { Some(n) } },
                status: match status_str.as_str() {
                    "active" => crate::master::TrustStatus::Active,
                    "revoked" => crate::master::TrustStatus::Revoked,
                    _ => crate::master::TrustStatus::Pending,
                },
                votes_approve: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or_default(),
                votes_reject: serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default(),
                requested_at: row.get(6)?,
                decided_at: row.get(7)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(entries)
    }

    pub fn load_trust_history(&self) -> Result<Vec<crate::master::TrustVote>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT voter_peer_id, target_peer_id, approve, timestamp FROM trust_history ORDER BY timestamp DESC")?;
        let votes = stmt.query_map([], |row| {
            Ok(crate::master::TrustVote {
                voter_peer_id: row.get(0)?, target_peer_id: row.get(1)?,
                approve: row.get::<_, i64>(2).unwrap_or(0) != 0, timestamp: row.get(3)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(votes)
    }

    // ─── Game Economy ─────────────────────────────────────────────────
    pub fn save_game_economy(&self, json: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("INSERT INTO game_economy (key, value) VALUES ('store', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![json])?;
        Ok(())
    }

    pub fn load_game_economy(&self) -> Option<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT value FROM game_economy WHERE key = 'store'", [], |r| r.get::<_, String>(0)).ok()
    }
}

// ─── Sync Logic ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum SyncDecision {
    SyncFrom { node_id: String },
    KeepLocal,
    LocalIsBetter,
}

pub fn decide_sync_direction(local_meta: &DbMetadata, remote_meta: &DbMetadata) -> SyncDecision {
    match remote_meta.table_count.cmp(&local_meta.table_count) {
        std::cmp::Ordering::Greater => SyncDecision::SyncFrom { node_id: remote_meta.node_id.clone() },
        std::cmp::Ordering::Less => SyncDecision::LocalIsBetter,
        std::cmp::Ordering::Equal => {
            if remote_meta.oldest_entry > 0 && remote_meta.oldest_entry < local_meta.oldest_entry {
                SyncDecision::SyncFrom { node_id: remote_meta.node_id.clone() }
            } else if local_meta.oldest_entry > 0 && local_meta.oldest_entry < remote_meta.oldest_entry {
                SyncDecision::LocalIsBetter
            } else {
                SyncDecision::KeepLocal
            }
        }
    }
}

pub fn find_best_remote(local_meta: &DbMetadata, network_meta: &[DbMetadata]) -> Option<DbMetadata> {
    network_meta.iter()
        .filter(|rm| {
            rm.table_count > local_meta.table_count
                || (rm.table_count == local_meta.table_count && rm.oldest_entry > 0 && rm.oldest_entry < local_meta.oldest_entry)
        })
        .max_by(|a, b| a.table_count.cmp(&b.table_count).then_with(|| b.oldest_entry.cmp(&a.oldest_entry)))
        .cloned()
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_longer_chain_wins() {
        let local = DbMetadata { table_count: 100, oldest_entry: 1000, newest_entry: 2000, node_id: "local".into() };
        let remote = DbMetadata { table_count: 200, oldest_entry: 500, newest_entry: 2500, node_id: "remote".into() };
        assert!(matches!(decide_sync_direction(&local, &remote), SyncDecision::SyncFrom { .. }));
    }

    #[test]
    fn test_sync_older_wins_on_tie() {
        let local = DbMetadata { table_count: 100, oldest_entry: 2000, newest_entry: 3000, node_id: "local".into() };
        let remote = DbMetadata { table_count: 100, oldest_entry: 1000, newest_entry: 3000, node_id: "remote".into() };
        assert!(matches!(decide_sync_direction(&local, &remote), SyncDecision::SyncFrom { .. }));
    }

    #[test]
    fn test_sync_absolute_tie() {
        let local = DbMetadata { table_count: 100, oldest_entry: 1000, newest_entry: 2000, node_id: "local".into() };
        let remote = DbMetadata { table_count: 100, oldest_entry: 1000, newest_entry: 2000, node_id: "remote".into() };
        assert!(matches!(decide_sync_direction(&local, &remote), SyncDecision::KeepLocal));
    }

    #[test]
    fn test_db_open_in_memory() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.user_count(), 0);
    }
}