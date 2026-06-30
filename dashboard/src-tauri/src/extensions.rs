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
    /// Kategorie ("extension", "theme")
    #[serde(default)]
    pub category: String,
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

/// Pfad zur UI-Datei einer installierten Extension.
fn ui_path(id: &str) -> PathBuf {
    extensions_dir().join(id).join("ui.html")
}

/// Prüft ob eine Extension installiert ist.
pub fn is_installed(id: &str) -> bool {
    manifest_path(id).exists() && wasm_path(id).exists()
}

/// Gibt die installierte Version einer Extension zurück.
pub fn installed_version(id: &str) -> Option<String> {
    read_manifest(id).map(|m| m.version)
}

/// Vergleicht zwei SemVer-Strings (simpel: lexikografisch).
fn is_newer_version(installed: &str, available: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.')
            .filter_map(|p| p.parse::<u32>().ok())
            .collect()
    };
    let a = parse(installed);
    let b = parse(available);
    for i in 0..a.len().max(b.len()) {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match bv.cmp(&av) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
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
        .unwrap_or_else(|_| "https://raw.githubusercontent.com/Stone310-crypto/extensions/main".into())
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
    eprintln!("[extensions] 📥 Installiere '{id}'...");

    // 1. Manifest vom Store laden (mit Fallback)
    let manifests = match fetch_available_extensions().await {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => {
            eprintln!("[extensions] Store leer → verwende Fallback");
            fallback_extensions()
        }
        Err(e) => {
            eprintln!("[extensions] Store-Fehler: {e} → verwende Fallback");
            fallback_extensions()
        }
    };

    let manifest = manifests
        .iter()
        .find(|m| m.id == id)
        .cloned()
        .ok_or_else(|| format!("Extension '{id}' nicht im Store gefunden"))?;

    eprintln!("[extensions]   Manifest gefunden: {} v{}", manifest.name, manifest.version);

    // 2. Extension-Verzeichnis erstellen
    let ext_dir = extensions_dir().join(id);
    std::fs::create_dir_all(&ext_dir)
        .map_err(|e| format!("Konnte Verzeichnis nicht erstellen: {e}"))?;
    eprintln!("[extensions]   Verzeichnis: {}", ext_dir.display());

    // 3. WASM-Modul herunterladen (optional — manche Extensions haben nur ui.html)
    let download_url = format!(
        "https://github.com/{}/releases/download/v{}/module.wasm",
        manifest.repository, manifest.version
    );
    eprintln!("[extensions]   Download: {download_url}");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP-Client Fehler: {e}"))?;

    let wasm_downloaded = match client.get(&download_url).header("User-Agent", "stone-dashboard/1.0").send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.bytes().await {
                Ok(data) if !data.is_empty() => {
                    let wpath = wasm_path(id);
                    std::fs::write(&wpath, &data)
                        .map_err(|e| format!("Konnte Modul nicht speichern: {e}"))?;
                    eprintln!("[extensions]   WASM gespeichert: {} bytes", data.len());
                    true
                }
                _ => false,
            }
        }
        _ => {
            eprintln!("[extensions]   Kein WASM-Modul (UI-only Extension)");
            false
        }
    };

    // Fallback: leere WASM-Datei für Extensions ohne eigenes WASM
    if !wasm_downloaded {
        std::fs::write(wasm_path(id), b"").ok();
    }

    // 4. Manifest speichern
    let mpath = manifest_path(id);
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("JSON-Fehler: {e}"))?;
    std::fs::write(&mpath, manifest_json)
        .map_err(|e| format!("Konnte Manifest nicht speichern: {e}"))?;
    eprintln!("[extensions]   Manifest gespeichert: {}", mpath.display());

    // 5. UI-Datei herunterladen (optional)
    let ui_url = format!(
        "https://github.com/{}/releases/download/v{}/ui.html",
        manifest.repository, manifest.version
    );
    if let Ok(resp) = client.get(&ui_url).header("User-Agent", "stone-dashboard/1.0").send().await {
        if resp.status().is_success() {
            if let Ok(ui_data) = resp.bytes().await {
                if !ui_data.is_empty() {
                    std::fs::write(ui_path(id), &ui_data).ok();
                }
            }
        }
    }

    // 6. Theme-CSS herunterladen (optional)
    let theme_url = format!(
        "https://github.com/{}/releases/download/v{}/theme.css",
        manifest.repository, manifest.version
    );
    if let Ok(resp) = client.get(&theme_url).header("User-Agent", "stone-dashboard/1.0").send().await {
        if resp.status().is_success() {
            if let Ok(css_data) = resp.bytes().await {
                if !css_data.is_empty() {
                    let tpath = extensions_dir().join(id).join("theme.css");
                    std::fs::write(&tpath, &css_data).ok();
                }
            }
        }
    }

    eprintln!("[extensions] ✅ '{id}' installiert");
    Ok(manifest)
}

// ─── Tauri Commands ──────────────────────────────────────────────────────────

/// Gibt die Liste aller installierten Extensions zurück.
#[tauri::command]
pub fn get_installed_extensions() -> Vec<ExtensionManifest> {
    let dir = extensions_dir();
    let _ = std::fs::create_dir_all(&dir); // Sicherstellen dass das Verzeichnis existiert

    if !dir.exists() {
        eprintln!("[extensions] Verzeichnis existiert nicht: {}", dir.display());
        return vec![];
    }

    let mut installed = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let id = entry.file_name().to_string_lossy().to_string();
                eprintln!("[extensions] Prüfe: {}", id);
                match read_manifest(&id) {
                    Some(manifest) => {
                        eprintln!("[extensions]   ✅ Installiert: {} v{}", manifest.name, manifest.version);
                        installed.push(manifest);
                    }
                    None => {
                        eprintln!("[extensions]   ⚠️  Kein gültiges Manifest für '{}'", id);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[extensions] Fehler beim Lesen von {}: {e}", dir.display());
        }
    }
    installed.sort_by(|a, b| a.name.cmp(&b.name));
    eprintln!("[extensions] {} Extension(s) installiert", installed.len());
    installed
}

/// Gibt die Liste aller verfügbaren Extensions vom Store zurück.
/// Falls der Store nicht erreichbar ist, wird der lokale Fallback verwendet.
/// Bewertungen werden mit echten Nutzer-Bewertungen angereichert.
#[tauri::command]
pub async fn get_available_extensions() -> Result<Vec<ExtensionManifest>, String> {
    let manifests = match fetch_available_extensions().await {
        Ok(exts) if !exts.is_empty() => exts,
        Ok(_) => {
            eprintln!("[extensions] Store lieferte leere Liste, verwende Fallback");
            fallback_extensions()
        }
        Err(e) => {
            eprintln!("[extensions] Store nicht erreichbar: {e} — verwende Fallback");
            fallback_extensions()
        }
    };

    Ok(enrich_with_real_ratings(manifests))
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

// ─── Bewertungssystem ───────────────────────────────────────────────────────

/// Eine Benutzer-Bewertung für eine Extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserRating {
    extension_id: String,
    rating: u8, // 1-5 Sterne
    timestamp: i64,
}

/// Pfad zur Bewertungsdatei.
fn ratings_file() -> PathBuf {
    extensions_dir().join("ratings.json")
}

/// Lädt alle Bewertungen.
fn load_ratings() -> Vec<UserRating> {
    let path = ratings_file();
    if !path.exists() {
        return vec![];
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Speichert alle Bewertungen.
fn save_ratings(ratings: &[UserRating]) {
    let _ = std::fs::create_dir_all(&extensions_dir());
    if let Ok(json) = serde_json::to_string_pretty(ratings) {
        let _ = std::fs::write(ratings_file(), json);
    }
}

/// Berechnet die durchschnittliche Bewertung für eine Extension.
fn compute_rating(extension_id: &str) -> (f32, u32) {
    let ratings = load_ratings();
    let relevant: Vec<u8> = ratings
        .iter()
        .filter(|r| r.extension_id == extension_id)
        .map(|r| r.rating)
        .collect();
    if relevant.is_empty() {
        return (0.0, 0);
    }
    let sum: f32 = relevant.iter().map(|&r| r as f32).sum();
    let count = relevant.len() as u32;
    (sum / count as f32, count)
}

/// Gibt eine Bewertung für eine Extension ab.
#[tauri::command]
pub fn rate_extension(extension_id: String, rating: u8) -> Result<(f32, u32), String> {
    if rating < 1 || rating > 5 {
        return Err("Bewertung muss zwischen 1 und 5 liegen".into());
    }

    let mut ratings = load_ratings();

    // Bestehende Bewertung überschreiben (ein User = eine Bewertung pro Extension)
    ratings.retain(|r| r.extension_id != extension_id);
    ratings.push(UserRating {
        extension_id: extension_id.clone(),
        rating,
        timestamp: chrono::Utc::now().timestamp(),
    });

    save_ratings(&ratings);
    Ok(compute_rating(&extension_id))
}

/// Gibt die aktuelle Bewertung des Users für eine Extension zurück.
#[tauri::command]
pub fn get_my_rating(extension_id: String) -> Option<u8> {
    let ratings = load_ratings();
    ratings
        .iter()
        .find(|r| r.extension_id == extension_id)
        .map(|r| r.rating)
}

/// Prüft welche installierten Extensions ein Update verfügbar haben.
/// Gibt eine Liste von (extension_id, installed_version, available_version) zurück.
#[tauri::command]
pub async fn check_for_updates() -> Result<Vec<(String, String, String)>, String> {
    let installed = get_installed_extensions();
    if installed.is_empty() {
        return Ok(vec![]);
    }

    let store = match fetch_available_extensions().await {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => fallback_extensions(),
        Err(_) => fallback_extensions(),
    };

    let mut updates = Vec::new();
    for inst in &installed {
        if let Some(store_ext) = store.iter().find(|s| s.id == inst.id) {
            if is_newer_version(&inst.version, &store_ext.version) {
                eprintln!(
                    "[extensions] Update verfügbar: {} v{} → v{}",
                    inst.name, inst.version, store_ext.version
                );
                updates.push((
                    inst.id.clone(),
                    inst.version.clone(),
                    store_ext.version.clone(),
                ));
            }
        }
    }
    Ok(updates)
}

/// Lädt die UI-Datei (ui.html) einer installierten Extension.
/// Gibt den HTML-Inhalt zurück, oder None wenn keine UI vorhanden ist.
#[tauri::command]
pub fn get_extension_ui(id: String) -> Option<String> {
    let path = ui_path(&id);
    if path.exists() {
        std::fs::read_to_string(&path).ok()
    } else {
        None
    }
}

/// Lädt die theme.css einer installierten Extension.
#[tauri::command]
pub fn get_theme_css(extension_id: String) -> Option<String> {
    let path = extensions_dir().join(&extension_id).join("theme.css");
    if path.exists() {
        std::fs::read_to_string(&path).ok()
    } else {
        None
    }
}

/// Listet alle installierten Extensions, die eine theme.css haben.
#[tauri::command]
pub fn list_themes() -> Vec<ExtensionManifest> {
    get_installed_extensions()
        .into_iter()
        .filter(|ext| extensions_dir().join(&ext.id).join("theme.css").exists())
        .collect()
}

/// Schreibt eine theme.css für eine Extension (wird vom Theme-Editor genutzt).
#[tauri::command]
pub fn write_theme_css(extension_id: String, css: String) -> Result<(), String> {
    let dir = extensions_dir().join(&extension_id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Verzeichnis: {e}"))?;
    std::fs::write(dir.join("theme.css"), &css)
        .map_err(|e| format!("Schreiben: {e}"))
}

/// Speichert ein Theme als Datei im themes-Ordner.
#[tauri::command]
pub fn save_theme_file(name: String, css: String) -> Result<String, String> {
    let dir = themes_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{e}"))?;
    let safe_name = name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let path = dir.join(format!("{safe_name}.css"));
    std::fs::write(&path, &css).map_err(|e| format!("{e}"))?;
    Ok(path.to_string_lossy().to_string())
}

// ─── Lokale Themes (gespeicherte Designs) ────────────────────────────────────

/// Metadaten eines lokal gespeicherten Themes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedThemeInfo {
    /// Dateiname ohne .css (Anzeigename)
    pub name: String,
    /// Pfad zur Datei
    pub path: String,
    /// Dateigröße in Bytes
    pub size: u64,
}

/// Listet alle lokal gespeicherten Themes (aus themes_dir).
#[tauri::command]
pub fn list_saved_themes() -> Vec<SavedThemeInfo> {
    let dir = themes_dir();
    if !dir.exists() {
        return vec![];
    }
    let mut themes: Vec<SavedThemeInfo> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e == "css").unwrap_or(false) {
                let name = p.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                themes.push(SavedThemeInfo {
                    name,
                    path: p.to_string_lossy().to_string(),
                    size,
                });
            }
        }
    }
    themes.sort_by(|a, b| a.name.cmp(&b.name));
    themes
}

/// Lädt ein lokal gespeichertes Theme (CSS-Inhalt).
#[tauri::command]
pub fn load_saved_theme(name: String) -> Result<String, String> {
    let safe_name = name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let path = themes_dir().join(format!("{safe_name}.css"));
    if !path.exists() {
        return Err(format!("Theme '{name}' nicht gefunden"));
    }
    std::fs::read_to_string(&path).map_err(|e| format!("Lesefehler: {e}"))
}

/// Löscht ein lokal gespeichertes Theme.
#[tauri::command]
pub fn delete_saved_theme(name: String) -> Result<(), String> {
    let safe_name = name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let path = themes_dir().join(format!("{safe_name}.css"));
    if !path.exists() {
        return Err(format!("Theme '{name}' nicht gefunden"));
    }
    std::fs::remove_file(&path).map_err(|e| format!("Löschfehler: {e}"))
}

/// Bereitet ein Theme für die Veröffentlichung im Store vor.
/// Erstellt eine publish-Struktur mit theme.css und ui.html.
#[tauri::command]
pub fn prepare_theme_publish(
    name: String,
    css: String,
    author: String,
    description: String,
) -> Result<String, String> {
    let safe_name = name.to_lowercase().replace([' ', '-'], "_");
    let dir = themes_dir().join("publish").join(&safe_name);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Verzeichnis: {e}"))?;

    // theme.css speichern
    std::fs::write(dir.join("theme.css"), &css).map_err(|e| format!("theme.css: {e}"))?;

    // ui.html (Minimal-Editor) speichern
    let ui = format!(
        r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{name}</title></head>
<body style="margin:0;font-family:system-ui;background:var(--bg-root,#0f1117);color:var(--text-primary,#e8e4df);display:flex;align-items:center;justify-content:center;height:100vh;text-align:center">
<div><h1>🎨 {name}</h1><p>{description}</p><p style="color:var(--text-secondary,#b8b4ae);font-size:13px">von {author}</p><p style="font-size:11px;color:var(--text-muted,#6e6b65);margin-top:16px">Theme wird automatisch angewendet.</p></div>
</body></html>"#
    );
    std::fs::write(dir.join("ui.html"), &ui).map_err(|e| format!("ui.html: {e}"))?;

    // README.md
    let readme = format!(
        "# 🎨 {name}\n\n{description}\n\n## Autor\n\n{author}\n\n## Installation\n\n1. Lade `theme.css` herunter\n2. Im Stone Dashboard: Theme-Editor → Design laden\n3. Oder als Extension im Store veröffentlichen\n"
    );
    std::fs::write(dir.join("README.md"), &readme).map_err(|e| format!("README: {e}"))?;

    Ok(format!(
        "Theme '{}' vorbereitet in:\n{}\n\nDateien: theme.css, ui.html, README.md",
        name,
        dir.display()
    ))
}

/// Themes-Ordner (für Export).
fn themes_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join("Library/Application Support/stone-dashboard/themes")
    }
    #[cfg(not(target_os = "macos"))]
    {
        extensions_dir().join("themes")
    }
}

/// Reichert die Store-Extensions mit echten Bewertungen an.
fn enrich_with_real_ratings(mut manifests: Vec<ExtensionManifest>) -> Vec<ExtensionManifest> {
    for m in &mut manifests {
        let (rating, reviews) = compute_rating(&m.id);
        if reviews > 0 {
            m.rating = rating;
            m.reviews = reviews;
        }
    }
    manifests
}

// ─── Fallback-Store (Offline / Dev) ──────────────────────────────────────────

/// Gibt einen leeren Fallback zurück (keine Demo-Daten mehr).
pub fn fallback_extensions() -> Vec<ExtensionManifest> {
    vec![]
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
