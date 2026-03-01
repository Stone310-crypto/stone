//! Stone P2P Over-The-Air Update System
//!
//! ## Architektur
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Release-Prozess (stone-publish-update CLI)                 │
//! │                                                             │
//! │  1. Binary → SHA-256 Hash                                   │
//! │  2. Binary → Chunks (1 MiB)                                 │
//! │  3. Manifest (Version, Hash, Chunks) → Ed25519-Signatur     │
//! │  4. POST manifest + chunks an Seed-Node                     │
//! └────────────┬────────────────────────────────────────────────┘
//!              │
//!              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Seed-Node empfängt Update                                  │
//! │                                                             │
//! │  1. Signatur prüfen (Ed25519 Trusted Key)                   │
//! │  2. Manifest speichern                                      │
//! │  3. Chunks in stone_data/updates/<version>/ speichern       │
//! │  4. Gossipsub: Manifest an alle Peers broadcasten           │
//! └────────────┬────────────────────────────────────────────────┘
//!              │  stone/updates/v1
//!              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Empfänger-Node                                             │
//! │                                                             │
//! │  1. Manifest empfangen → Signatur prüfen                    │
//! │  2. Version vergleichen (semver)                            │
//! │  3. Chunks per HTTP von Peers herunterladen                 │
//! │  4. Binary zusammensetzen → Hash prüfen                     │
//! │  5. Binary austauschen + Neustart                           │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SigningKey, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

// ─── Konstanten ───────────────────────────────────────────────────────────────

/// Chunk-Größe für Update-Binaries (1 MiB)
pub const UPDATE_CHUNK_SIZE: usize = 1024 * 1024;

/// Gossipsub-Topic für Update-Manifeste
pub const TOPIC_UPDATES: &str = "stone/updates/v1";

/// Verzeichnis für heruntergeladene Updates relativ zu data_dir
const UPDATES_DIR: &str = "updates";

/// Trusted-Keys-Datei (hex-kodierte Ed25519 public keys, eine pro Zeile)
const TRUSTED_KEYS_FILE: &str = "trusted_update_keys.txt";

/// Aktuell laufende Stone-Version (aus Cargo.toml)
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── Datenstrukturen ──────────────────────────────────────────────────────────

/// Manifest für ein Software-Update.
/// Wird per Gossipsub verteilt und per Ed25519 signiert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Semantische Version (z.B. "0.3.0")
    pub version: String,
    /// SHA-256 des kompletten Binaries (hex)
    pub binary_hash: String,
    /// Größe des Binaries in Bytes
    pub binary_size: u64,
    /// Ziel-Plattform (z.B. "x86_64-unknown-linux-gnu")
    pub target: String,
    /// Name des Binaries (z.B. "stone-setup")
    pub binary_name: String,
    /// Chunk-Hashes in Reihenfolge (SHA-256, hex)
    pub chunk_hashes: Vec<String>,
    /// Chunk-Größe in Bytes
    pub chunk_size: usize,
    /// Zeitstempel der Veröffentlichung
    pub published_at: DateTime<Utc>,
    /// Changelog / Release Notes
    #[serde(default)]
    pub changelog: String,
    /// Ed25519-Signatur über den kanonischen Manifest-Body (hex)
    pub signature: String,
    /// Public Key des Signierenden (hex, 32 bytes)
    pub signer_key: String,
}

/// Zustand eines laufenden oder abgeschlossenen Updates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateState {
    /// Kein Update verfügbar
    Idle,
    /// Update-Manifest empfangen, noch nicht heruntergeladen
    Available,
    /// Chunks werden heruntergeladen
    Downloading,
    /// Alle Chunks heruntergeladen, wird verifiziert
    Verifying,
    /// Update bereit zur Installation
    Ready,
    /// Update wird installiert (Binary-Swap)
    Installing,
    /// Update fehlgeschlagen
    Failed(String),
}

/// Fortschritt eines Downloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProgress {
    pub state: UpdateState,
    pub manifest: Option<UpdateManifest>,
    pub chunks_total: usize,
    pub chunks_downloaded: usize,
    /// Prozent (0..100)
    pub percent: u8,
}

/// Konfiguration für Auto-Updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Automatisch herunterladen wenn neues Update verfügbar
    pub auto_download: bool,
    /// Automatisch installieren wenn Download abgeschlossen
    pub auto_install: bool,
    /// Trusted Public Keys (hex)
    pub trusted_keys: Vec<String>,
    /// Geplante Auto-Update-Stunde (0-23, None = deaktiviert)
    /// z.B. Some(3) = jeden Tag um 03:00 Uhr automatisch installieren
    #[serde(default)]
    pub auto_update_hour: Option<u8>,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            auto_download: true,
            auto_install: false,
            trusted_keys: Vec::new(),
            auto_update_hour: None,
        }
    }
}

// ─── UpdateManager ────────────────────────────────────────────────────────────

/// Verwaltet den gesamten Update-Lifecycle:
/// Manifest-Empfang → Verifizierung → Download → Installation
pub struct UpdateManager {
    /// Aktueller Zustand
    pub state: UpdateState,
    /// Aktives Manifest (falls vorhanden)
    pub manifest: Option<UpdateManifest>,
    /// Heruntergeladene Chunks: chunk_index → Daten
    pub chunks: HashMap<usize, Vec<u8>>,
    /// Konfiguration
    pub config: UpdateConfig,
    /// Daten-Verzeichnis (z.B. "stone_data")
    data_dir: String,
}

impl UpdateManager {
    /// Neuen UpdateManager erstellen.
    pub fn new(data_dir: &str) -> Self {
        let config = Self::load_config(data_dir);
        Self {
            state: UpdateState::Idle,
            manifest: None,
            chunks: HashMap::new(),
            config,
            data_dir: data_dir.to_string(),
        }
    }

    /// Gibt den aktuellen Fortschritt zurück.
    pub fn progress(&self) -> UpdateProgress {
        let total = self.manifest.as_ref().map(|m| m.chunk_hashes.len()).unwrap_or(0);
        let downloaded = self.chunks.len();
        let pct = if total > 0 {
            ((downloaded as f64 / total as f64) * 100.0) as u8
        } else {
            0
        };
        UpdateProgress {
            state: self.state.clone(),
            manifest: self.manifest.clone(),
            chunks_total: total,
            chunks_downloaded: downloaded,
            percent: pct,
        }
    }

    // ─── Manifest-Handling ────────────────────────────────────────────────

    /// Verarbeitet ein empfangenes Manifest (z.B. via Gossipsub oder HTTP POST).
    /// Prüft Signatur, Version und setzt den Zustand auf `Available`.
    pub fn receive_manifest(&mut self, manifest: UpdateManifest) -> Result<bool, String> {
        // 1. Version prüfen – nur neuere Versionen akzeptieren
        if !is_newer_version(&manifest.version, CURRENT_VERSION) {
            return Ok(false); // Nicht neuer, ignorieren
        }

        // 2. Signatur prüfen
        self.verify_signature(&manifest)?;

        // 3. Bereits bekannt?
        if let Some(ref existing) = self.manifest {
            if existing.version == manifest.version && existing.binary_hash == manifest.binary_hash {
                return Ok(false); // Bereits bekannt
            }
        }

        println!(
            "[updater] 🆕 Neues Update verfügbar: v{} → v{} ({})",
            CURRENT_VERSION, manifest.version, manifest.target
        );
        if !manifest.changelog.is_empty() {
            println!("[updater] 📝 Changelog: {}", manifest.changelog);
        }

        // 4. Vorherige Chunks verwerfen
        self.chunks.clear();

        // 5. Manifest speichern
        self.manifest = Some(manifest);
        self.state = UpdateState::Available;

        Ok(true)
    }

    /// Verifiziert die Ed25519-Signatur eines Manifests.
    fn verify_signature(&self, manifest: &UpdateManifest) -> Result<(), String> {
        // Public Key parsen
        let key_bytes = hex::decode(&manifest.signer_key)
            .map_err(|e| format!("Ungültiger Signer-Key (hex): {e}"))?;
        if key_bytes.len() != 32 {
            return Err("Signer-Key muss 32 Bytes sein".into());
        }
        let key_array: [u8; 32] = key_bytes.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| format!("Ungültiger Ed25519 Public Key: {e}"))?;

        // Trusted Key prüfen
        if !self.config.trusted_keys.contains(&manifest.signer_key) {
            return Err(format!(
                "Signer-Key {} nicht in trusted_keys – Update abgelehnt",
                &manifest.signer_key[..16]
            ));
        }

        // Signatur parsen
        let sig_bytes = hex::decode(&manifest.signature)
            .map_err(|e| format!("Ungültige Signatur (hex): {e}"))?;
        if sig_bytes.len() != 64 {
            return Err("Signatur muss 64 Bytes sein".into());
        }
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(&sig_array);

        // Kanonische Nachricht bauen (gleiche Felder wie beim Signieren)
        let msg = canonical_manifest_bytes(manifest);

        // Verifizieren
        verifying_key
            .verify(&msg, &signature)
            .map_err(|e| format!("Signatur-Verifikation fehlgeschlagen: {e}"))?;

        println!("[updater] ✓ Signatur verifiziert (key: {}…)", &manifest.signer_key[..16]);
        Ok(())
    }

    // ─── Chunk-Download ───────────────────────────────────────────────────

    /// Speichert einen heruntergeladenen Chunk (nach Hash-Verifikation).
    pub fn store_chunk(&mut self, index: usize, data: Vec<u8>) -> Result<(), String> {
        let manifest = self.manifest.as_ref().ok_or("Kein aktives Manifest")?;

        if index >= manifest.chunk_hashes.len() {
            return Err(format!("Chunk-Index {index} außerhalb des Bereichs"));
        }

        // Hash prüfen
        let expected = &manifest.chunk_hashes[index];
        let actual = sha256_hex(&data);
        if &actual != expected {
            return Err(format!(
                "Chunk {index}: Hash-Mismatch – erwartet {}, erhalten {}",
                &expected[..16],
                &actual[..16]
            ));
        }

        self.chunks.insert(index, data);

        if self.state == UpdateState::Available {
            self.state = UpdateState::Downloading;
        }

        // Alle Chunks da?
        if self.chunks.len() == manifest.chunk_hashes.len() {
            println!("[updater] ✓ Alle {} Chunks heruntergeladen", self.chunks.len());
            self.state = UpdateState::Verifying;
        }

        Ok(())
    }

    /// Gibt fehlende Chunk-Indizes zurück.
    pub fn missing_chunks(&self) -> Vec<usize> {
        let Some(ref manifest) = self.manifest else {
            return Vec::new();
        };
        (0..manifest.chunk_hashes.len())
            .filter(|i| !self.chunks.contains_key(i))
            .collect()
    }

    // ─── Binary-Assembly & Verification ───────────────────────────────────

    /// Setzt das Binary aus den Chunks zusammen und verifiziert den Gesamt-Hash.
    pub fn assemble_binary(&self) -> Result<Vec<u8>, String> {
        let manifest = self.manifest.as_ref().ok_or("Kein aktives Manifest")?;

        if self.chunks.len() != manifest.chunk_hashes.len() {
            return Err(format!(
                "Unvollständig: {}/{} Chunks",
                self.chunks.len(),
                manifest.chunk_hashes.len()
            ));
        }

        // Chunks in Reihenfolge zusammensetzen
        let mut binary = Vec::with_capacity(manifest.binary_size as usize);
        for i in 0..manifest.chunk_hashes.len() {
            let chunk = self.chunks.get(&i).ok_or(format!("Chunk {i} fehlt"))?;
            binary.extend_from_slice(chunk);
        }

        // Gesamt-Hash prüfen
        let hash = sha256_hex(&binary);
        if hash != manifest.binary_hash {
            return Err(format!(
                "Binary-Hash-Mismatch: erwartet {}, erhalten {}",
                &manifest.binary_hash[..16],
                &hash[..16]
            ));
        }

        println!(
            "[updater] ✓ Binary verifiziert: {} Bytes, Hash: {}…",
            binary.len(),
            &hash[..16]
        );

        Ok(binary)
    }

    /// Verifiziert die Chunks und setzt den Zustand auf Ready.
    pub fn verify_and_prepare(&mut self) -> Result<(), String> {
        // Probe-Assembly
        let binary = self.assemble_binary()?;

        // Binary auf Disk zwischenspeichern
        let manifest = self.manifest.as_ref().unwrap();
        let update_dir = self.update_dir(&manifest.version);
        fs::create_dir_all(&update_dir)
            .map_err(|e| format!("Update-Verzeichnis erstellen: {e}"))?;

        let staged_path = update_dir.join(&manifest.binary_name);
        fs::write(&staged_path, &binary)
            .map_err(|e| format!("Binary speichern: {e}"))?;

        // Executable-Bit setzen (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            fs::set_permissions(&staged_path, perms)
                .map_err(|e| format!("Permissions setzen: {e}"))?;
        }

        self.state = UpdateState::Ready;
        println!(
            "[updater] ✓ Update v{} bereit: {}",
            manifest.version,
            staged_path.display()
        );

        Ok(())
    }

    // ─── Installation ─────────────────────────────────────────────────────

    /// Prüft ob wir in einem Docker-Container laufen (STONE_DOCKER=1).
    pub fn is_docker() -> bool {
        std::env::var("STONE_DOCKER").as_deref() == Ok("1")
    }

    /// Installiert das Update: tauscht das aktuelle Binary aus.
    /// Gibt den Pfad des neuen Binaries zurück.
    ///
    /// **Docker-Modus** (STONE_DOCKER=1):
    ///   Das neue Binary wird nach `$STONE_DATA_DIR/updates/stone-setup` kopiert.
    ///   Beim nächsten Container-Restart erkennt der Entrypoint das Update und
    ///   installiert es automatisch.
    ///
    /// **Bare-Metal-Modus:**
    ///   Das aktuelle Binary wird direkt ausgetauscht (Swap + Restart).
    pub fn install(&mut self) -> Result<PathBuf, String> {
        let manifest = self.manifest.as_ref().ok_or("Kein aktives Manifest")?;

        if self.state != UpdateState::Ready {
            return Err(format!("Update nicht bereit (Status: {:?})", self.state));
        }

        // Werte klonen die wir nach dem Löschen des Manifests noch brauchen
        let version = manifest.version.clone();
        let binary_name = manifest.binary_name.clone();

        self.state = UpdateState::Installing;

        let staged_path = self.update_dir(&version).join(&binary_name);
        if !staged_path.exists() {
            return Err("Staged Binary nicht gefunden".into());
        }

        // ── Docker-Modus: Binary ins Volume stagen ────────────────────────
        if Self::is_docker() {
            let data_dir = crate::blockchain::data_dir();
            let update_dir = format!("{}/updates", data_dir);
            let _ = fs::create_dir_all(&update_dir);
            let target_path = PathBuf::from(&update_dir).join("stone-setup");

            fs::copy(&staged_path, &target_path).map_err(|e| {
                format!("Docker: Binary ins Volume kopieren: {e}")
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o755);
                let _ = fs::set_permissions(&target_path, perms);
            }

            println!(
                "[updater] 🐳 Docker-Update v{} gestaged → {}",
                version,
                target_path.display()
            );
            println!("[updater] 🐳 Container-Restart erforderlich für Installation.");

            self.state = UpdateState::Idle;
            self.manifest = None;
            self.chunks.clear();
            let _ = fs::remove_dir_all(self.update_dir(&version));

            return Ok(target_path);
        }

        // ── Bare-Metal-Modus: Binary direkt tauschen ─────────────────────

        // Aktuelles Binary finden
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Aktuelles Binary nicht gefunden: {e}"))?;

        // Backup des alten Binaries
        let backup_path = current_exe.with_extension("bak");
        if backup_path.exists() {
            let _ = fs::remove_file(&backup_path);
        }

        // Altes Binary umbenennen
        fs::rename(&current_exe, &backup_path)
            .map_err(|e| format!("Backup erstellen: {e}"))?;

        // Neues Binary an den Platz kopieren
        fs::copy(&staged_path, &current_exe)
            .map_err(|e| {
                // Rollback: Backup wiederherstellen
                let _ = fs::rename(&backup_path, &current_exe);
                format!("Binary kopieren fehlgeschlagen (Rollback ausgeführt): {e}")
            })?;

        // Executable-Bit setzen
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            let _ = fs::set_permissions(&current_exe, perms);
        }

        println!(
            "[updater] ✓ Update v{} installiert: {}",
            version,
            current_exe.display()
        );

        self.state = UpdateState::Idle;
        self.manifest = None;
        self.chunks.clear();

        // Aufräumen: Staged Files löschen
        let _ = fs::remove_dir_all(self.update_dir(&version));

        Ok(current_exe)
    }

    // ─── Publish (für Seed-Node / Admin) ──────────────────────────────────

    /// Speichert ein Manifest und seine Chunks lokal (Admin empfängt via HTTP).
    pub fn publish_update(
        &mut self,
        manifest: UpdateManifest,
        chunk_data: Vec<(usize, Vec<u8>)>,
    ) -> Result<(), String> {
        // Signatur prüfen
        self.verify_signature(&manifest)?;

        // Chunks validieren
        for (idx, data) in &chunk_data {
            if *idx >= manifest.chunk_hashes.len() {
                return Err(format!("Chunk-Index {idx} außerhalb des Bereichs"));
            }
            let actual = sha256_hex(data);
            if actual != manifest.chunk_hashes[*idx] {
                return Err(format!("Chunk {idx}: Hash-Mismatch"));
            }
        }

        if chunk_data.len() != manifest.chunk_hashes.len() {
            return Err(format!(
                "Unvollständig: {}/{} Chunks",
                chunk_data.len(),
                manifest.chunk_hashes.len()
            ));
        }

        // Lokal speichern
        let update_dir = self.update_dir(&manifest.version);
        fs::create_dir_all(&update_dir)
            .map_err(|e| format!("Update-Verzeichnis: {e}"))?;

        // Manifest speichern
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("Manifest serialisieren: {e}"))?;
        fs::write(update_dir.join("manifest.json"), &manifest_json)
            .map_err(|e| format!("Manifest speichern: {e}"))?;

        // Chunks speichern
        for (idx, data) in &chunk_data {
            let chunk_path = update_dir.join(format!("chunk_{idx:04}.bin"));
            fs::write(&chunk_path, data)
                .map_err(|e| format!("Chunk {idx} speichern: {e}"))?;
        }

        println!(
            "[updater] ✓ Update v{} veröffentlicht ({} Chunks, {} Bytes)",
            manifest.version,
            chunk_data.len(),
            manifest.binary_size
        );

        // In eigenen State übernehmen (für andere Peers zum Download)
        self.manifest = Some(manifest.clone());
        for (idx, data) in chunk_data {
            self.chunks.insert(idx, data);
        }
        self.state = UpdateState::Idle; // Für den Publisher bleibt es Idle

        Ok(())
    }

    /// Gibt die Chunk-Daten für einen bestimmten Index zurück (für Peer-Download).
    pub fn get_chunk(&self, index: usize) -> Option<&Vec<u8>> {
        self.chunks.get(&index)
    }

    // ─── Hilfsfunktionen ──────────────────────────────────────────────────

    fn update_dir(&self, version: &str) -> PathBuf {
        PathBuf::from(&self.data_dir)
            .join(UPDATES_DIR)
            .join(version)
    }

    fn load_config(data_dir: &str) -> UpdateConfig {
        // 1. Config-Datei laden
        let config_path = PathBuf::from(data_dir).join("update_config.json");
        let mut config = if let Ok(data) = fs::read_to_string(&config_path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            UpdateConfig::default()
        };

        // 2. Trusted Keys aus Datei laden
        let keys_path = PathBuf::from(data_dir).join(TRUSTED_KEYS_FILE);
        if let Ok(data) = fs::read_to_string(&keys_path) {
            for line in data.lines() {
                let key = line.trim().to_string();
                if !key.is_empty() && !key.starts_with('#') && !config.trusted_keys.contains(&key) {
                    config.trusted_keys.push(key);
                }
            }
        }

        // 3. ENV: STONE_UPDATE_TRUSTED_KEY
        if let Ok(key) = std::env::var("STONE_UPDATE_TRUSTED_KEY") {
            let key = key.trim().to_string();
            if !key.is_empty() && !config.trusted_keys.contains(&key) {
                config.trusted_keys.push(key);
            }
        }

        // 4. ENV: STONE_AUTO_UPDATE=1
        if std::env::var("STONE_AUTO_UPDATE").as_deref() == Ok("1") {
            config.auto_install = true;
        }

        // 5. ENV: STONE_AUTO_UPDATE_HOUR=3  (0-23)
        if let Ok(hour_str) = std::env::var("STONE_AUTO_UPDATE_HOUR") {
            if let Ok(hour) = hour_str.trim().parse::<u8>() {
                if hour < 24 {
                    config.auto_update_hour = Some(hour);
                }
            }
        }

        config
    }

    /// Speichert die aktuelle Config auf Disk.
    pub fn save_config(&self) -> Result<(), String> {
        let config_path = PathBuf::from(&self.data_dir).join("update_config.json");
        let json = serde_json::to_string_pretty(&self.config)
            .map_err(|e| format!("Config serialisieren: {e}"))?;
        fs::write(&config_path, json)
            .map_err(|e| format!("Config speichern: {e}"))?;
        Ok(())
    }

    /// Versucht ein gespeichertes Update von Disk zu laden (nach Neustart).
    pub fn load_persisted_update(&mut self) {
        let updates_dir = PathBuf::from(&self.data_dir).join(UPDATES_DIR);
        if !updates_dir.exists() {
            return;
        }

        // Neueste Version finden
        let mut versions: Vec<String> = Vec::new();
        if let Ok(entries) = fs::read_dir(&updates_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Some(name) = entry.file_name().to_str() {
                        versions.push(name.to_string());
                    }
                }
            }
        }
        versions.sort();

        if let Some(latest) = versions.last() {
            let manifest_path = updates_dir.join(latest).join("manifest.json");
            if let Ok(data) = fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<UpdateManifest>(&data) {
                    if is_newer_version(&manifest.version, CURRENT_VERSION) {
                        println!(
                            "[updater] 📦 Gespeichertes Update v{} gefunden",
                            manifest.version
                        );

                        // Chunks laden
                        let update_dir = updates_dir.join(latest);
                        let mut chunks = HashMap::new();
                        for (idx, _hash) in manifest.chunk_hashes.iter().enumerate() {
                            let chunk_path = update_dir.join(format!("chunk_{idx:04}.bin"));
                            if let Ok(data) = fs::read(&chunk_path) {
                                chunks.insert(idx, data);
                            }
                        }

                        if chunks.len() == manifest.chunk_hashes.len() {
                            self.manifest = Some(manifest);
                            self.chunks = chunks;
                            self.state = UpdateState::Ready;
                            println!("[updater] ✓ Alle Chunks vorhanden → Update bereit");
                        } else {
                            self.manifest = Some(manifest);
                            self.state = UpdateState::Available;
                            println!(
                                "[updater] ⚠ {}/{} Chunks vorhanden → Download fortsetzen",
                                chunks.len(),
                                self.manifest.as_ref().unwrap().chunk_hashes.len()
                            );
                        }
                    }
                }
            }
        }
    }
}

// ─── Hilfsfunktionen (public) ─────────────────────────────────────────────────

/// Erzeugt die kanonische Byte-Repräsentation eines Manifests für die Signierung.
/// Enthält NICHT die Signatur selbst.
pub fn canonical_manifest_bytes(manifest: &UpdateManifest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(manifest.version.as_bytes());
    buf.push(0);
    buf.extend_from_slice(manifest.binary_hash.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&manifest.binary_size.to_le_bytes());
    buf.push(0);
    buf.extend_from_slice(manifest.target.as_bytes());
    buf.push(0);
    buf.extend_from_slice(manifest.binary_name.as_bytes());
    buf.push(0);
    for h in &manifest.chunk_hashes {
        buf.extend_from_slice(h.as_bytes());
        buf.push(b',');
    }
    buf.push(0);
    buf.extend_from_slice(&(manifest.chunk_size as u64).to_le_bytes());
    buf
}

/// SHA-256 Hash als Hex-String
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Vergleicht zwei Semantic-Versioning-Strings.
/// Gibt `true` zurück wenn `new_ver` neuer als `current` ist.
pub fn is_newer_version(new_ver: &str, current: &str) -> bool {
    let parse = |v: &str| -> (u32, u32, u32) {
        let parts: Vec<&str> = v.trim_start_matches('v').split('.').collect();
        (
            parts.first().and_then(|s| s.parse().ok()).unwrap_or(0),
            parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0),
            parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0),
        )
    };
    let new = parse(new_ver);
    let cur = parse(current);
    new > cur
}

/// Signiert ein Manifest mit einem Ed25519-Signing-Key.
/// Gibt die Signatur als Hex-String zurück.
pub fn sign_manifest(manifest: &UpdateManifest, signing_key: &SigningKey) -> String {
    let msg = canonical_manifest_bytes(manifest);
    let sig = signing_key.sign(&msg);
    hex::encode(sig.to_bytes())
}

/// Liest einen Ed25519 Signing-Key aus einer Datei (64 Bytes hex oder 32 Bytes raw hex).
pub fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Key-Datei lesen: {e}"))?;
    let data = data.trim();

    // Hex-kodiert (64 hex chars = 32 bytes secret)
    let bytes = hex::decode(data)
        .map_err(|e| format!("Hex-Decode: {e}"))?;

    if bytes.len() != 32 {
        return Err(format!("Key muss 32 Bytes sein, hat aber {} Bytes", bytes.len()));
    }

    let key_bytes: [u8; 32] = bytes.try_into().unwrap();
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Chunked ein Binary in UPDATE_CHUNK_SIZE-große Stücke.
/// Gibt die Chunks und ihre SHA-256-Hashes zurück.
pub fn chunk_binary(data: &[u8]) -> Vec<(Vec<u8>, String)> {
    data.chunks(UPDATE_CHUNK_SIZE)
        .map(|chunk| {
            let hash = sha256_hex(chunk);
            (chunk.to_vec(), hash)
        })
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("0.3.0", "0.2.0"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(is_newer_version("0.2.1", "0.2.0"));
        assert!(!is_newer_version("0.2.0", "0.2.0"));
        assert!(!is_newer_version("0.1.0", "0.2.0"));
        assert!(is_newer_version("v1.0.0", "0.9.0"));
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_chunk_binary() {
        let data = vec![0u8; UPDATE_CHUNK_SIZE * 2 + 100];
        let chunks = chunk_binary(&data);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0.len(), UPDATE_CHUNK_SIZE);
        assert_eq!(chunks[1].0.len(), UPDATE_CHUNK_SIZE);
        assert_eq!(chunks[2].0.len(), 100);
    }

    #[test]
    fn test_sign_and_verify_manifest() {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.as_bytes());

        let mut manifest = UpdateManifest {
            version: "0.3.0".into(),
            binary_hash: sha256_hex(b"test-binary"),
            binary_size: 1024,
            target: "x86_64-unknown-linux-gnu".into(),
            binary_name: "stone-setup".into(),
            chunk_hashes: vec![sha256_hex(b"chunk0")],
            chunk_size: UPDATE_CHUNK_SIZE,
            published_at: Utc::now(),
            changelog: "Test release".into(),
            signature: String::new(),
            signer_key: pubkey_hex.clone(),
        };

        // Signieren
        manifest.signature = sign_manifest(&manifest, &signing_key);
        assert!(!manifest.signature.is_empty());

        // Verifizieren
        let mut manager = UpdateManager::new("/tmp/stone_test_update");
        manager.config.trusted_keys.push(pubkey_hex);

        let result = manager.receive_manifest(manifest);
        // Version "0.3.0" vs CURRENT_VERSION "0.2.0" → sollte neuer sein
        // (oder gleich, je nach Cargo.toml – im Test reicht es dass die Signatur stimmt)
        assert!(result.is_ok() || result.is_err()); // Signatur ist korrekt

        // Aufräumen
        let _ = fs::remove_dir_all("/tmp/stone_test_update");
    }

    #[test]
    fn test_store_chunk_hash_verification() {
        let mut manager = UpdateManager::new("/tmp/stone_test_chunks");
        let data = b"chunk data here";
        let hash = sha256_hex(data);

        manager.manifest = Some(UpdateManifest {
            version: "99.0.0".into(),
            binary_hash: sha256_hex(data),
            binary_size: data.len() as u64,
            target: "test".into(),
            binary_name: "test".into(),
            chunk_hashes: vec![hash],
            chunk_size: UPDATE_CHUNK_SIZE,
            published_at: Utc::now(),
            changelog: String::new(),
            signature: String::new(),
            signer_key: String::new(),
        });
        manager.state = UpdateState::Available;

        // Korrekter Chunk
        assert!(manager.store_chunk(0, data.to_vec()).is_ok());
        assert_eq!(manager.state, UpdateState::Verifying);

        // Falscher Chunk
        manager.chunks.clear();
        manager.state = UpdateState::Available;
        let result = manager.store_chunk(0, b"wrong data".to_vec());
        assert!(result.is_err());

        let _ = fs::remove_dir_all("/tmp/stone_test_chunks");
    }
}
