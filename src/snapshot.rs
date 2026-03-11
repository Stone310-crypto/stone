//! Stone Snapshot — Schneller Node-Bootstrap
//!
//! Ein Snapshot ist ein komprimiertes Abbild des gesamten Node-Zustands:
//!
//! - `chain_db/`   — RocksDB (Blöcke, Meta, Index)
//! - `token_db/`   — Token-Ledger (Balancen, Staking, Reputation)
//! - `checkpoints.json` — Finalisierte Checkpoints
//! - `validator_set.json` — Validator-Registry
//! - `shard_holders.json` — Shard-Verteilung
//!
//! ## Format
//!
//! `snapshot_<height>_<genesis_prefix>.tar.zst`
//!
//! Die Datei enthält ein tar-Archiv, zstd-komprimiert.
//! Zusätzlich wird eine `snapshot.json` Metadatei erstellt.
//!
//! ## Ablauf
//!
//! 1. **Erstellen**: `create_snapshot()` — friert RocksDB-Checkpoint ein, packt alles
//! 2. **Bereitstellen**: HTTP `GET /api/v1/snapshot` oder P2P `SnapshotRequest`
//! 3. **Laden**: `restore_snapshot()` — entpackt ins Datenverzeichnis, danach normaler Start
//! 4. **Auto-Erstellung**: Alle `SNAPSHOT_INTERVAL` Blöcke wird ein neuer Snapshot erstellt

use crate::blockchain::data_dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

// ─── Konfiguration ───────────────────────────────────────────────────────────

/// Alle N Blöcke wird automatisch ein Snapshot erstellt.
pub const SNAPSHOT_INTERVAL: u64 = 200;

/// Maximale Anzahl beibehaltener Snapshots (älteste werden gelöscht).
pub const MAX_SNAPSHOTS: usize = 3;

/// Minimale Chain-Höhe bevor der erste Snapshot erstellt wird.
pub const MIN_SNAPSHOT_HEIGHT: u64 = 50;

// ─── Snapshot Metadata ───────────────────────────────────────────────────────

/// Metadaten eines Snapshots – wird als `snapshot.json` im Snapshot-Verzeichnis gespeichert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Chain-Höhe zum Zeitpunkt des Snapshots
    pub block_height: u64,
    /// Genesis-Block-Hash (zur Kompatibilitätsprüfung)
    pub genesis_hash: String,
    /// Hash des letzten Blocks im Snapshot
    pub latest_hash: String,
    /// SHA-256 des tar.zst Archivs
    pub archive_hash: String,
    /// Größe des Archivs in Bytes
    pub archive_size: u64,
    /// Unix-Timestamp der Erstellung
    pub created_at: i64,
    /// Node-Version
    pub node_version: String,
    /// Dateiname des Archivs
    pub filename: String,
}

// ─── Pfade ───────────────────────────────────────────────────────────────────

/// Verzeichnis für Snapshots: `stone_data/snapshots/`
pub fn snapshot_dir() -> PathBuf {
    let dir = PathBuf::from(data_dir()).join("snapshots");
    fs::create_dir_all(&dir).unwrap_or(());
    dir
}

/// Pfad zur aktuellen Snapshot-Metadatei.
pub fn latest_snapshot_meta_path() -> PathBuf {
    snapshot_dir().join("latest.json")
}

// ─── Snapshot erstellen ──────────────────────────────────────────────────────

/// Erstellt einen Snapshot des aktuellen Node-Zustands.
///
/// # Ablauf
/// 1. Erstellt einen RocksDB-Checkpoint (konsistenter Snapshot der DB)
/// 2. Packt chain_db, token_db, und JSON-Konfigurationsdateien in ein tar-Archiv
/// 3. Komprimiert mit zstd (Level 3 – guter Kompromiss Geschwindigkeit/Größe)
/// 4. Erstellt Metadaten (Höhe, Genesis-Hash, Archiv-Hash)
/// 5. Bereinigt alte Snapshots
///
/// Gibt den Pfad zum erstellten Archiv und die Metadaten zurück.
pub fn create_snapshot(
    block_height: u64,
    genesis_hash: &str,
    latest_hash: &str,
) -> Result<(PathBuf, SnapshotMeta), SnapshotError> {
    let dd = data_dir();
    let snap_dir = snapshot_dir();

    // Alte .tmp-Dateien bereinigen (Überreste abgebrochener Snapshots)
    cleanup_tmp_files(&snap_dir);

    let genesis_prefix = &genesis_hash[..12.min(genesis_hash.len())];
    let filename = format!("snapshot_{block_height}_{genesis_prefix}.tar.zst");
    let archive_path = snap_dir.join(&filename);
    // Atomic write: erst in .tmp schreiben, dann umbenennen
    let tmp_archive_path = snap_dir.join(format!("{filename}.tmp"));

    // Temporäres Verzeichnis für den RocksDB-Checkpoint
    let tmp_checkpoint = snap_dir.join(format!("_tmp_cp_{block_height}"));
    if tmp_checkpoint.exists() {
        fs::remove_dir_all(&tmp_checkpoint)?;
    }

    // RocksDB-Checkpoint erstellen (read-only open, kein Lock-Konflikt)
    {
        let chain_db_path = format!("{}/chain_db", dd);
        let chain_cp_dst = tmp_checkpoint.join("chain_db");
        create_rocksdb_checkpoint(&chain_db_path, &chain_cp_dst)?;
    }

    // token_db ebenfalls als Checkpoint kopieren
    {
        let token_db_path = format!("{}/token_db", dd);
        if Path::new(&token_db_path).exists() {
            let token_cp_dst = tmp_checkpoint.join("token_db");
            create_rocksdb_checkpoint(&token_db_path, &token_cp_dst)?;
        }
    }

    // JSON-Dateien kopieren (chain-relevante Dateien, KEINE node-spezifischen wie p2p_config)
    let json_files = [
        "checkpoints.json",
        "validators.json",
        "shard_holders.json",
    ];
    for fname in &json_files {
        let src = format!("{}/{}", dd, fname);
        if Path::new(&src).exists() {
            let dst = tmp_checkpoint.join(fname);
            fs::copy(&src, &dst)?;
        }
    }

    // tar.zst in temporäre Datei erstellen
    eprintln!("[snapshot] 📦 Erstelle Snapshot bei Block #{block_height}...");
    let archive_file = fs::File::create(&tmp_archive_path)?;
    let zst_encoder = zstd::Encoder::new(archive_file, 3)?;
    let mut tar_builder = tar::Builder::new(zst_encoder);

    // Alle Dateien im tmp_checkpoint rekursiv hinzufügen
    tar_builder.append_dir_all(".", &tmp_checkpoint)?;
    let zst_encoder = tar_builder.into_inner()?;
    zst_encoder.finish()?;

    // Aufräumen: temporäres Checkpoint-Verzeichnis löschen
    fs::remove_dir_all(&tmp_checkpoint)?;

    // Atomar: temporäre Datei zum finalen Pfad umbenennen
    fs::rename(&tmp_archive_path, &archive_path)?;

    // SHA-256 über das Archiv berechnen
    let archive_hash = sha256_file(&archive_path)?;
    let archive_size = fs::metadata(&archive_path)?.len();

    let meta = SnapshotMeta {
        block_height,
        genesis_hash: genesis_hash.to_string(),
        latest_hash: latest_hash.to_string(),
        archive_hash,
        archive_size,
        created_at: chrono::Utc::now().timestamp(),
        node_version: env!("CARGO_PKG_VERSION").to_string(),
        filename: filename.clone(),
    };

    // Metadaten atomar schreiben (tmp + rename)
    let meta_path = snap_dir.join(format!("snapshot_{block_height}_{genesis_prefix}.json"));
    let meta_json = serde_json::to_string_pretty(&meta)?;
    let tmp_meta = meta_path.with_extension("json.tmp");
    fs::write(&tmp_meta, &meta_json)?;
    fs::rename(&tmp_meta, &meta_path)?;

    // latest.json atomar aktualisieren
    let latest_path = latest_snapshot_meta_path();
    let tmp_latest = latest_path.with_extension("json.tmp");
    fs::write(&tmp_latest, &meta_json)?;
    fs::rename(&tmp_latest, &latest_path)?;

    eprintln!(
        "[snapshot] ✅ Snapshot erstellt: {} ({:.1} MB, Block #{block_height})",
        filename,
        archive_size as f64 / 1_048_576.0
    );

    // Alte Snapshots aufräumen
    cleanup_old_snapshots(MAX_SNAPSHOTS);

    Ok((archive_path, meta))
}

/// Erstellt einen RocksDB-Checkpoint (hardlinks, sehr schnell).
///
/// WICHTIG: `dst_path` darf NICHT existieren — RocksDB erstellt es selbst.
/// Öffnet die DB im Read-Only Modus um Lock-Konflikte mit dem laufenden Node zu vermeiden.
fn create_rocksdb_checkpoint(db_path: &str, dst_path: &Path) -> Result<(), SnapshotError> {
    use rocksdb::{Options, DB};

    if !Path::new(db_path).exists() {
        return Ok(()); // DB existiert nicht — überspringe
    }

    // Sicherstellen, dass dst_path NICHT existiert (RocksDB-Anforderung)
    if dst_path.exists() {
        fs::remove_dir_all(dst_path)?;
    }

    let mut opts = Options::default();
    opts.create_if_missing(false);

    // Read-Only Open: kein Lock-Konflikt mit dem laufenden Node-Prozess
    let db = if db_path.ends_with("chain_db") {
        // chain_db hat 3 CFs + default
        DB::open_cf_for_read_only(&opts, db_path, ["default", "blocks", "meta", "index"], false)
    } else {
        DB::open_for_read_only(&opts, db_path, false)
    }.map_err(|e| SnapshotError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("RocksDB read-only open {db_path}: {e}"),
    )))?;

    let cp = rocksdb::checkpoint::Checkpoint::new(&db)
        .map_err(|e| SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Checkpoint::new {db_path}: {e}"),
        )))?;

    cp.create_checkpoint(dst_path)
        .map_err(|e| SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Checkpoint create {}: {e}", dst_path.display()),
        )))?;

    Ok(())
}

// ─── Snapshot wiederherstellen ───────────────────────────────────────────────

/// Stellt einen Snapshot aus einem tar.zst-Archiv wieder her.
///
/// **ACHTUNG**: Überschreibt die bestehenden chain_db und token_db!
///
/// # Ablauf
/// 1. Archiv-Hash verifizieren
/// 2. Bestehende DBs sichern (rename)
/// 3. tar.zst entpacken ins Datenverzeichnis
/// 4. Alte Backup-DBs löschen
pub fn restore_snapshot(
    archive_path: &Path,
    expected_meta: &SnapshotMeta,
) -> Result<(), SnapshotError> {
    let dd = data_dir();

    // 1. Archiv-Hash verifizieren
    let actual_hash = sha256_file(archive_path)?;
    if actual_hash != expected_meta.archive_hash {
        return Err(SnapshotError::HashMismatch {
            expected: expected_meta.archive_hash.clone(),
            actual: actual_hash,
        });
    }

    eprintln!(
        "[snapshot] 🔄 Stelle Snapshot wieder her: Block #{}, {:.1} MB",
        expected_meta.block_height,
        expected_meta.archive_size as f64 / 1_048_576.0
    );

    // 2. Bestehende DBs sichern
    let chain_db = format!("{}/chain_db", dd);
    let token_db = format!("{}/token_db", dd);
    let chain_db_backup = format!("{}/chain_db.pre_snapshot", dd);
    let token_db_backup = format!("{}/token_db.pre_snapshot", dd);

    // Alte Backups löschen
    let _ = fs::remove_dir_all(&chain_db_backup);
    let _ = fs::remove_dir_all(&token_db_backup);

    // Bestehende DBs umbenennen (falls vorhanden)
    if Path::new(&chain_db).exists() {
        fs::rename(&chain_db, &chain_db_backup)?;
    }
    if Path::new(&token_db).exists() {
        fs::rename(&token_db, &token_db_backup)?;
    }

    // 3. p2p_config.json VOR dem Entpacken sichern (enthält lokale PeerId)
    let own_p2p_config = PathBuf::from(format!("{}/p2p_config.json", dd));
    let p2p_backup = PathBuf::from(format!("{}/p2p_config.json.local_backup", dd));
    let had_p2p_config = if own_p2p_config.exists() {
        fs::copy(&own_p2p_config, &p2p_backup).ok();
        true
    } else {
        false
    };

    // 4. Entpacken
    let archive_file = fs::File::open(archive_path)?;
    let zst_decoder = zstd::Decoder::new(archive_file)?;
    let mut tar_archive = tar::Archive::new(zst_decoder);

    // In data_dir entpacken
    let dd_path = PathBuf::from(&dd);
    fs::create_dir_all(&dd_path)?;
    if let Err(e) = tar_archive.unpack(&dd_path) {
        // Unpack fehlgeschlagen → Backups wiederherstellen
        eprintln!("[snapshot] ⚠️  Unpack fehlgeschlagen, stelle Backups wieder her: {e}");
        if Path::new(&chain_db_backup).exists() {
            let _ = fs::rename(&chain_db_backup, &chain_db);
        }
        if Path::new(&token_db_backup).exists() {
            let _ = fs::rename(&token_db_backup, &token_db);
        }
        if had_p2p_config {
            let _ = fs::rename(&p2p_backup, &own_p2p_config);
        }
        return Err(SnapshotError::Io(e));
    }

    // 5. Backups löschen (Snapshot erfolgreich)
    let _ = fs::remove_dir_all(&chain_db_backup);
    let _ = fs::remove_dir_all(&token_db_backup);

    // 6. Lokale p2p_config.json wiederherstellen (enthält eigene PeerId)
    if had_p2p_config {
        // Snapshot-Version der p2p_config umbenennen, lokale wiederherstellen
        let snapshot_p2p = PathBuf::from(format!("{}/p2p_config.json.snapshot", dd));
        let _ = fs::rename(&own_p2p_config, &snapshot_p2p);
        let _ = fs::rename(&p2p_backup, &own_p2p_config);
    }

    eprintln!(
        "[snapshot] ✅ Snapshot wiederhergestellt: Block #{}, Genesis: {}...",
        expected_meta.block_height,
        &expected_meta.genesis_hash[..12.min(expected_meta.genesis_hash.len())]
    );

    Ok(())
}

// ─── Snapshot vom Netzwerk holen ─────────────────────────────────────────────

/// Versucht einen Snapshot von einem HTTP-Peer herunterzuladen.
///
/// # Ablauf
/// 1. GET /api/v1/snapshot/meta — Metadaten holen
/// 2. Genesis-Hash vergleichen
/// 3. GET /api/v1/snapshot/download — Archiv herunterladen
/// 4. Hash verifizieren
/// 5. Wiederherstellen
pub async fn download_snapshot_from_peer(
    peer_url: &str,
    local_genesis_hash: &str,
    local_chain_height: u64,
) -> Result<SnapshotMeta, SnapshotError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 Min Timeout für große Snapshots
        .connect_timeout(std::time::Duration::from_secs(5)) // Schneller Connect-Timeout
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
        .map_err(|e| SnapshotError::Network(format!("HTTP-Client: {e}")))?;

    // 1. Metadaten holen (kurzer Timeout – schnell weiter bei nicht-verfügbaren Peers)
    let meta_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
        .map_err(|e| SnapshotError::Network(format!("HTTP-Client: {e}")))?;

    let meta_url = format!("{}/api/v1/snapshot/meta", peer_url.trim_end_matches('/'));
    let meta_resp = meta_client.get(&meta_url).send().await
        .map_err(|e| SnapshotError::Network(format!("Snapshot-Meta von {peer_url}: {e}")))?;

    if !meta_resp.status().is_success() {
        return Err(SnapshotError::Network(
            format!("{peer_url}: Snapshot nicht verfügbar (HTTP {})", meta_resp.status())
        ));
    }

    let meta: SnapshotMeta = meta_resp.json().await
        .map_err(|e| SnapshotError::Network(format!("Snapshot-Meta parse: {e}")))?;

    // 2. Genesis-Check
    if !local_genesis_hash.is_empty() && meta.genesis_hash != local_genesis_hash {
        return Err(SnapshotError::GenesisMismatch {
            local: local_genesis_hash.to_string(),
            remote: meta.genesis_hash,
        });
    }

    // 3. Snapshot nur holen wenn er deutlich weiter ist als unsere Chain
    let min_advantage = 50; // Mindestens 50 Blöcke Vorsprung
    if meta.block_height <= local_chain_height + min_advantage {
        return Err(SnapshotError::NotWorthIt {
            local: local_chain_height,
            remote: meta.block_height,
        });
    }

    eprintln!(
        "[snapshot] 📥 Lade Snapshot von {peer_url}: Block #{}, {:.1} MB",
        meta.block_height,
        meta.archive_size as f64 / 1_048_576.0
    );

    // 4. Archiv herunterladen (chunked — kein vollständiges Laden in RAM)
    let dl_url = format!("{}/api/v1/snapshot/download", peer_url.trim_end_matches('/'));
    let mut dl_resp = client.get(&dl_url).send().await
        .map_err(|e| SnapshotError::Network(format!("Snapshot-Download: {e}")))?;

    if !dl_resp.status().is_success() {
        return Err(SnapshotError::Network(
            format!("Snapshot-Download fehlgeschlagen: HTTP {}", dl_resp.status())
        ));
    }

    // In Datei streamen (chunk-weise, nicht alles in RAM)
    let snap_dir = snapshot_dir();
    let tmp_archive_path = snap_dir.join(format!("{}.tmp", &meta.filename));
    let archive_path = snap_dir.join(&meta.filename);
    {
        let mut file = fs::File::create(&tmp_archive_path)?;
        while let Some(chunk) = dl_resp.chunk().await
            .map_err(|e| SnapshotError::Network(format!("Snapshot-Download lesen: {e}")))?
        {
            std::io::Write::write_all(&mut file, &chunk)?;
        }
    }
    // Atomar: tmp → final
    fs::rename(&tmp_archive_path, &archive_path)?;

    // 5. Hash verifizieren
    let actual_hash = sha256_file(&archive_path)?;
    if actual_hash != meta.archive_hash {
        let _ = fs::remove_file(&archive_path);
        return Err(SnapshotError::HashMismatch {
            expected: meta.archive_hash.clone(),
            actual: actual_hash,
        });
    }

    eprintln!(
        "[snapshot] ✅ Snapshot heruntergeladen und verifiziert: Block #{}",
        meta.block_height
    );

    // 6. Wiederherstellen
    restore_snapshot(&archive_path, &meta)?;

    Ok(meta)
}

/// Prüft ob ein Snapshot erstellt werden soll (alle SNAPSHOT_INTERVAL Blöcke).
pub fn should_create_snapshot(block_height: u64) -> bool {
    if block_height < MIN_SNAPSHOT_HEIGHT {
        return false;
    }
    block_height % SNAPSHOT_INTERVAL == 0
}

/// Prüft ob ein Snapshot nach einem Sync erstellt werden soll.
///
/// Während eines Batch-Syncs kann die exakte 200er-Grenze übersprungen werden
/// (z.B. Sync von Block 100 → 350). Diese Funktion prüft ob IRGENDEINE
/// Snapshot-Grenze zwischen `pre_sync_height` und `post_sync_height` liegt.
///
/// Gibt die höchste übersprungene Snapshot-Grenze zurück (oder None).
pub fn crossed_snapshot_boundary(pre_sync_height: u64, post_sync_height: u64) -> Option<u64> {
    if post_sync_height < MIN_SNAPSHOT_HEIGHT {
        return None;
    }
    // Höchste 200er-Grenze die <= post_sync_height ist
    let latest_boundary = (post_sync_height / SNAPSHOT_INTERVAL) * SNAPSHOT_INTERVAL;
    // Wurde diese Grenze während des Syncs übersprungen?
    if latest_boundary > pre_sync_height && latest_boundary >= MIN_SNAPSHOT_HEIGHT {
        Some(latest_boundary)
    } else {
        None
    }
}

/// Lädt die Metadaten des neuesten lokalen Snapshots.
pub fn latest_snapshot() -> Option<SnapshotMeta> {
    let path = latest_snapshot_meta_path();
    if !path.exists() {
        return None;
    }
    let data = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/// SHA-256 eines Dateipfads.
fn sha256_file(path: &Path) -> Result<String, SnapshotError> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Bereinigt .tmp-Dateien und _tmp_cp-Verzeichnisse im Snapshot-Verzeichnis.
fn cleanup_tmp_files(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
            if name.ends_with(".tmp") || name.starts_with("_tmp_cp_") {
                if path.is_dir() {
                    let _ = fs::remove_dir_all(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
                eprintln!("[snapshot] 🗑️  Stale tmp bereinigt: {name}");
            }
        }
    }
}

/// Bereinigt alte Snapshots, behält nur die neuesten `keep` Stück.
fn cleanup_old_snapshots(keep: usize) {
    let dir = snapshot_dir();
    let mut snapshots: Vec<(PathBuf, PathBuf, i64)> = Vec::new();

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false)
                && path.file_name().map(|f| f.to_string_lossy().starts_with("snapshot_")).unwrap_or(false)
                && !path.file_name().map(|f| f == "latest.json").unwrap_or(false)
            {
                // Metadaten lesen und created_at extrahieren
                if let Ok(data) = fs::read_to_string(&path) {
                    if let Ok(meta) = serde_json::from_str::<SnapshotMeta>(&data) {
                        let archive_path = dir.join(&meta.filename);
                        snapshots.push((path.clone(), archive_path, meta.created_at));
                    }
                }
            }
        }
    }

    // Nach Erstellungsdatum sortieren (neueste zuerst)
    snapshots.sort_by(|a, b| b.2.cmp(&a.2));

    // Alte löschen
    for (meta_path, archive_path, _) in snapshots.iter().skip(keep) {
        let _ = fs::remove_file(meta_path);
        let _ = fs::remove_file(archive_path);
        eprintln!(
            "[snapshot] 🗑️  Alter Snapshot gelöscht: {}",
            archive_path.file_name().map(|f| f.to_string_lossy()).unwrap_or_default()
        );
    }
}

// ─── Fehler ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SnapshotError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Network(String),
    HashMismatch { expected: String, actual: String },
    GenesisMismatch { local: String, remote: String },
    /// Snapshot ist nicht genug weiter als die lokale Chain
    NotWorthIt { local: u64, remote: u64 },
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO: {e}"),
            Self::Json(e) => write!(f, "JSON: {e}"),
            Self::Network(s) => write!(f, "Netzwerk: {s}"),
            Self::HashMismatch { expected, actual } =>
                write!(f, "Hash-Mismatch: erwartet {expected}, bekommen {actual}"),
            Self::GenesisMismatch { local, remote } =>
                write!(f, "Genesis-Mismatch: lokal={local}, remote={remote}"),
            Self::NotWorthIt { local, remote } =>
                write!(f, "Snapshot nicht lohnenswert: lokal={local}, remote={remote}"),
        }
    }
}

impl From<std::io::Error> for SnapshotError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

impl From<serde_json::Error> for SnapshotError {
    fn from(e: serde_json::Error) -> Self { Self::Json(e) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_create_snapshot() {
        assert!(!should_create_snapshot(0));
        assert!(!should_create_snapshot(49));
        assert!(!should_create_snapshot(100)); // 100 >= 50 aber 100 % 200 != 0
        assert!(should_create_snapshot(200));
        assert!(should_create_snapshot(400));
        assert!(!should_create_snapshot(201));
    }

    #[test]
    fn test_crossed_snapshot_boundary() {
        // Kein Crossing: beide unter MIN_SNAPSHOT_HEIGHT
        assert_eq!(crossed_snapshot_boundary(0, 49), None);
        // Kein Crossing: gleiche Seite der Grenze
        assert_eq!(crossed_snapshot_boundary(201, 350), None);
        // Crossing: 100 → 350 überspringt die 200er-Grenze
        assert_eq!(crossed_snapshot_boundary(100, 350), Some(200));
        // Crossing: 100 → 500 überspringt 200 und 400 → gibt die höchste (400) zurück
        assert_eq!(crossed_snapshot_boundary(100, 500), Some(400));
        // Exakter Treffer: 100 → 200
        assert_eq!(crossed_snapshot_boundary(100, 200), Some(200));
        // Kein Crossing: Start und Ende in gleicher Intervall-Periode
        assert_eq!(crossed_snapshot_boundary(200, 250), None);
        // Crossing: 199 → 200
        assert_eq!(crossed_snapshot_boundary(199, 200), Some(200));
    }

    #[test]
    fn test_snapshot_meta_serde() {
        let meta = SnapshotMeta {
            block_height: 500,
            genesis_hash: "abc123".to_string(),
            latest_hash: "def456".to_string(),
            archive_hash: "fff000".to_string(),
            archive_size: 1024,
            created_at: 1700000000,
            node_version: "0.7.6".to_string(),
            filename: "test.tar.zst".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let decoded: SnapshotMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.block_height, 500);
        assert_eq!(decoded.genesis_hash, "abc123");
    }
}
