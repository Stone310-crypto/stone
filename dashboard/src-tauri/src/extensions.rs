//! Extension-Manager für Stone Dashboard.
//!
//! Verwaltet optionale Erweiterungen (Extensions), die vom Extension-Store
//! heruntergeladen und installiert werden können.
//!
//! ## Architektur
//!
//! - **Manifest**: Metadaten (Name, Version, Beschreibung, Bewertung, etc.)
//! - **Installation**: Download → Signatur-Prüfung → Entpacken → Speichern
//! - **Laufzeit**: WASM-Module werden dynamisch geladen
//!
//! ## Verzeichnisstruktur
//!
//! ```text
//! extensions/
//!   gaming/
//!     manifest.json
//!     module.wasm
//!   dashboard/
//!     manifest.json
//!     module.wasm
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Extension-Manifest ──────────────────────────────────────────────────────

/// Manifest einer Extension (wird im Store angezeigt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionManifest {
    /// Eindeutige ID (z.B. "gaming", "dashboard")
    pub id: String,
    /// Anzeigename
    pub name: String,
    /// Kurzbeschreibung
    pub description: String,
    /// Version (SemVer)
    pub version: String,
    /// Emoji-Icon
    pub icon: String,
    /// Bewertung (1.0 - 5.0)
    pub rating: f32,
    /// Anzahl Bewertungen
    pub reviews: u32,
    /// Anzahl Downloads
    pub downloads: u32,
    /// Größe in MB
    pub size_mb: u32,
    /// GitHub-Repository (z.B. "stonechain/gaming-extension")
    pub repository: String,
    /// Erforderliche Berechtigungen
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Autor
    #[serde(default)]
    pub author: String,
}

// ─── Extension-Dateisystem ───────────────────────────────────────────────────

/// Basis-Verzeichnis für Extensions.
pub fn extensions_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home)
            .join("Library/Application Support/stone-dashboard")
            .join("extensions")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/share/stone-dashboard/extensions")
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        PathBuf::from(appdata).join("stone-dashboard/extensions")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("./extensions")
    }
}

/// Pfad zum Manifest einer installierten Extension.
fn manifest_path(id: &str) -> PathBuf {
    extensions_dir().join(id).join("manifest.json")
}

/// Pfad zum WASM-Modul einer installierten Extension.
fn wasm_path(id: &str) -> PathBuf {
    extensions_dir().join(id).join("module.wasm")
}

/// Prüft ob eine Extension installiert ist.
pub fn is_installed(id: &str) -> bool {
    manifest_path(id).exists() && wasm_path(id).exists()
}

/// Liest das Manifest einer installierten Extension.
pub fn read_manifest(id: &str) -> Option<ExtensionManifest> {
    let path = manifest_path(id);
    if !path.exists() {
        return None;
    }
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Löscht eine installierte Extension.
pub fn uninstall_extension(id: &str) -> Result<(), String> {
    let dir = extensions_dir().join(id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| format!("Konnte Extension '{id}' nicht löschen: {e}"))?;
    }
    Ok(())
}

// ─── Extension-Store (GitHub API) ────────────────────────────────────────────

/// Extension-Store URL (kann per Env-Var überschrieben werden).
fn store_api_base() -> String {
    std::env::var("STONE_EXTENSION_STORE_URL")
        .unwrap_or_else(|_| "https://raw.githubusercontent.com/stonechain/extensions/main".into())
}

/// Lädt die Liste aller verfügbaren Extensions vom Store.
pub async fn fetch_available_extensions() -> Result<Vec<ExtensionManifest>, String> {
    let url = format!("{}/index.json", store_api_base());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP-Client Fehler: {e}"))?;

    let resp = client
        .get(&url)
        .header("User-Agent", "stone-dashboard/1.0")
        .send()
        .await
        .map_err(|e| format!("Store nicht erreichbar: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Store antwortete mit HTTP {}", resp.status()));
    }

    let manifests: Vec<ExtensionManifest> = resp
        .json()
        .await
        .map_err(|e| format!("Ungültiges Store-Format: {e}"))?;

    Ok(manifests)
}

/// Lädt eine Extension herunter und installiert sie.
pub async fn install_extension(id: &str) -> Result<ExtensionManifest, String> {
    // 1. Manifest vom Store laden
    let manifests = fetch_available_extensions().await?;
    let manifest = manifests
        .iter()
        .find(|m| m.id == id)
        .cloned()
        .ok_or_else(|| format!("Extension '{id}' nicht im Store gefunden"))?;

    // 2. WASM-Modul herunterladen
    let download_url = format!(
        "https://github.com/{}/releases/download/v{}/module.wasm",
        manifest.repository, manifest.version
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP-Client Fehler: {e}"))?;

    let data = client
        .get(&download_url)
        .header("User-Agent", "stone-dashboard/1.0")
        .send()
        .await
        .map_err(|e| format!("Download fehlgeschlagen: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("Daten konnten nicht gelesen werden: {e}"))?;

    // 3. TODO: Signatur-Prüfung
    // verify_extension_signature(&data, &manifest)?;

    // 4. Extension-Verzeichnis erstellen
    let ext_dir = extensions_dir().join(id);
    std::fs::create_dir_all(&ext_dir)
        .map_err(|e| format!("Konnte Verzeichnis nicht erstellen: {e}"))?;

    // 5. WASM-Modul speichern
    std::fs::write(wasm_path(id), &data)
        .map_err(|e| format!("Konnte Modul nicht speichern: {e}"))?;

    // 6. Manifest speichern
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("JSON-Fehler: {e}"))?;
    std::fs::write(manifest_path(id), manifest_json)
        .map_err(|e| format!("Konnte Manifest nicht speichern: {e}"))?;

    Ok(manifest)
}

// ─── Tauri Commands ──────────────────────────────────────────────────────────

/// Gibt die Liste aller installierten Extensions zurück.
#[tauri::command]
pub fn get_installed_extensions() -> Vec<ExtensionManifest> {
    let dir = extensions_dir();
    if !dir.exists() {
        return vec![];
    }

    let mut installed = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let id = entry.file_name().to_string_lossy().to_string();
            if let Some(manifest) = read_manifest(&id) {
                installed.push(manifest);
            }
        }
    }
    installed.sort_by(|a, b| a.name.cmp(&b.name));
    installed
}

/// Gibt die Liste aller verfügbaren Extensions vom Store zurück.
/// Falls der Store nicht erreichbar ist, wird der lokale Fallback verwendet.
#[tauri::command]
pub async fn get_available_extensions() -> Result<Vec<ExtensionManifest>, String> {
    match fetch_available_extensions().await {
        Ok(exts) if !exts.is_empty() => Ok(exts),
        Ok(_) => {
            // Store lieferte leere Liste → Fallback
            eprintln!("[extensions] Store lieferte leere Liste, verwende Fallback");
            Ok(fallback_extensions())
        }
        Err(e) => {
            eprintln!("[extensions] Store nicht erreichbar: {e} — verwende Fallback");
            Ok(fallback_extensions())
        }
    }
}

/// Installiert eine Extension aus dem Store.
#[tauri::command]
pub async fn cmd_install_extension(id: String) -> Result<ExtensionManifest, String> {
    install_extension(&id).await
}

/// Deinstalliert eine Extension.
#[tauri::command]
pub fn cmd_uninstall_extension(id: String) -> Result<(), String> {
    uninstall_extension(&id)
}

// ─── Fallback-Store (Offline / Dev) ──────────────────────────────────────────

/// Gibt einen lokalen Fallback-Store zurück (für Offline-Entwicklung).
pub fn fallback_extensions() -> Vec<ExtensionManifest> {
    vec![
        ExtensionManifest {
            id: "gaming".into(),
            name: "Gaming-Modul".into(),
            description: "Spiele-Registrierung, Item-Trading, Marktplatz & In-Game-Assets".into(),
            version: "1.0.0".into(),
            icon: "🎮".into(),
            rating: 4.8,
            reviews: 42,
            downloads: 1_230,
            size_mb: 10,
            repository: "stonechain/gaming-extension".into(),
            permissions: vec!["network".into(), "storage".into()],
            author: "StoneChain".into(),
        },
        ExtensionManifest {
            id: "dashboard".into(),
            name: "Dashboard-Modul".into(),
            description: "Grafiken, Statistiken & Node-Monitoring".into(),
            version: "1.0.0".into(),
            icon: "📊".into(),
            rating: 4.2,
            reviews: 15,
            downloads: 890,
            size_mb: 8,
            repository: "stonechain/dashboard-extension".into(),
            permissions: vec!["network".into(), "storage".into()],
            author: "StoneChain".into(),
        },
        ExtensionManifest {
            id: "2fa".into(),
            name: "2FA-Modul".into(),
            description: "Zwei-Faktor-Authentifizierung für Wallet-Transaktionen".into(),
            version: "1.0.0".into(),
            icon: "🔐".into(),
            rating: 4.9,
            reviews: 8,
            downloads: 340,
            size_mb: 3,
            repository: "stonechain/2fa-extension".into(),
            permissions: vec!["wallet".into()],
            author: "StoneChain".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_has_extensions() {
        let exts = fallback_extensions();
        assert_eq!(exts.len(), 3);
        assert_eq!(exts[0].id, "gaming");
        assert_eq!(exts[1].id, "dashboard");
        assert_eq!(exts[2].id, "2fa");
    }

    #[test]
    fn test_manifest_serialization() {
        let m = ExtensionManifest {
            id: "test".into(),
            name: "Test".into(),
            description: "Desc".into(),
            version: "1.0.0".into(),
            icon: "🧪".into(),
            rating: 5.0,
            reviews: 1,
            downloads: 0,
            size_mb: 1,
            repository: "test/repo".into(),
            permissions: vec![],
            author: "Dev".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: ExtensionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "test");
    }
}
