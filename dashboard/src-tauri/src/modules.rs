//! Modulares Plugin-System für Stone Dashboard.
//!
//! ## Architektur
//!
//! Die App besteht aus einem **Core** (Messenger, Wallet, Explorer, Node-Manager)
//! und **optionalen Modulen** (Gaming, Full-Node), die zur Laufzeit geladen
//! oder nachinstalliert werden können.
//!
//! ## Feature-Detection
//!
//! - **Build-time**: Cargo-Features (`cfg!(feature = "gaming-module")`)
//! - **Runtime**: Dynamische `.dylib`/`.so`/`.dll` Module im `modules/` Ordner
//!
//! ## Modul-Typen
//!
//! | Modul          | Feature-Flag     | Runtime-Datei        |
//! |----------------|------------------|----------------------|
//! | Core (Messenger, Wallet, Explorer, Node-Manager) | immer an | — |
//! | Gaming         | `gaming-module`  | `modules/gaming.dylib` |
//! | Full Node      | `node-module`    | `modules/node.dylib`   |

use serde::Serialize;
use std::path::PathBuf;

// ─── Modul-Info ──────────────────────────────────────────────────────────────

/// Beschreibt ein optionales Modul.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    /// Eindeutiger Modul-Name (z.B. "gaming", "node")
    pub name: String,
    /// Anzeigename (z.B. "Gaming-Modul")
    pub display_name: String,
    /// Kurzbeschreibung
    pub description: String,
    /// Ist das Modul aktuell verfügbar (entweder via Feature oder als Datei)?
    pub available: bool,
    /// Ist es via Build-Feature eingebaut?
    pub built_in: bool,
    /// Pfad zur Runtime-Datei (falls als Datei vorhanden)
    pub file_path: Option<String>,
    /// Download-URL für das Modul
    pub download_url: String,
    /// Geschätzte Größe in MB
    pub size_mb: u32,
    /// Icon/Emoji für die UI
    pub icon: String,
}

// ─── Modul-Registry ──────────────────────────────────────────────────────────

/// Gibt die Liste aller bekannten optionalen Module zurück.
/// Dynamisch: erkennt ALLE installierten Extensions mit ui.html.
pub fn get_optional_modules() -> Vec<ModuleInfo> {
    let installed = crate::extensions::get_installed_extensions();

    // Hardcoded Module (immer im Store anzeigbar, auch wenn nicht installiert)
    let mut modules = vec![
        ModuleInfo {
            name: "gaming".into(),
            display_name: "Gaming".into(),
            description: "Spiele-Registrierung, Item-Trading, Marktplatz & In-Game-Assets".into(),
            available: is_module_available("gaming"),
            built_in: cfg!(feature = "gaming-module"),
            file_path: find_module_file("gaming"),
            download_url: "https://updates.stonechain.dev/modules/gaming.tar.gz".into(),
            size_mb: 10,
            icon: "🎮".into(),
        },
        ModuleInfo {
            name: "node".into(),
            display_name: "Node".into(),
            description: "Node-Status, Mining & Netzwerk".into(),
            available: is_module_available("node"),
            built_in: cfg!(feature = "node-module"),
            file_path: find_module_file("node"),
            download_url: "https://updates.stonechain.dev/modules/node.tar.gz".into(),
            size_mb: 15,
            icon: "🖥️".into(),
        },
    ];

    // Dynamisch: alle installierten Extensions mit ui.html hinzufügen
    for ext in &installed {
        // Nicht doppelt (gaming/node sind schon oben)
        if modules.iter().any(|m| m.name == ext.id) {
            // Update available flag
            if let Some(m) = modules.iter_mut().find(|m| m.name == ext.id) {
                m.available = true;
                m.file_path = Some(format!("extensions/{}/ui.html", ext.id));
            }
            continue;
        }

        // Neue Extension → in die NavRail aufnehmen
        let has_ui = std::path::Path::new(&format!(
            "{}/{}/ui.html",
            crate::extensions::extensions_dir().display(),
            ext.id
        ))
        .exists();

        if has_ui {
            modules.push(ModuleInfo {
                name: ext.id.clone(),
                display_name: ext.name.clone(),
                description: ext.description.clone(),
                available: true,
                built_in: false,
                file_path: Some(format!("extensions/{}/ui.html", ext.id)),
                download_url: format!(
                    "https://github.com/{}/releases/latest",
                    ext.repository
                ),
                size_mb: ext.size_mb,
                icon: ext.icon.clone(),
            });
        }
    }

    modules
}

/// Gibt die Liste der Core-Features zurück (immer verfügbar).
pub fn get_core_modules() -> Vec<ModuleInfo> {
    vec![
        ModuleInfo {
            name: "messenger".into(),
            display_name: "Messenger".into(),
            description: "Chat, Server & Kontakte".into(),
            available: true,
            built_in: true,
            file_path: None,
            download_url: String::new(),
            size_mb: 0,
            icon: "💬".into(),
        },
        ModuleInfo {
            name: "wallet".into(),
            display_name: "Wallet".into(),
            description: "Balance & Transaktionen".into(),
            available: true,
            built_in: true,
            file_path: None,
            download_url: String::new(),
            size_mb: 0,
            icon: "💰".into(),
        },
        ModuleInfo {
            name: "explorer".into(),
            display_name: "Explorer".into(),
            description: "Onchain-Daten anzeigen".into(),
            available: true,
            built_in: true,
            file_path: None,
            download_url: String::new(),
            size_mb: 0,
            icon: "🔍".into(),
        },
        ModuleInfo {
            name: "node-manager".into(),
            display_name: "Node-Manager".into(),
            description: "Verbindung zu Nodes".into(),
            available: true,
            built_in: true,
            file_path: None,
            download_url: String::new(),
            size_mb: 0,
            icon: "🔗".into(),
        },
    ]
}

// ─── Modul-Verfügbarkeit prüfen ──────────────────────────────────────────────

/// Prüft ob ein Modul verfügbar ist (Build-Feature ODER Runtime-Datei ODER Extension).
fn is_module_available(name: &str) -> bool {
    // 1. Build-time Feature?
    match name {
        "gaming" if cfg!(feature = "gaming-module") => return true,
        "node" if cfg!(feature = "node-module") => return true,
        _ => {}
    }

    // 2. Runtime-Datei vorhanden?
    if find_module_file(name).is_some() {
        return true;
    }

    // 3. Extension installiert? (Extensions-System)
    if crate::extensions::is_installed(name) {
        return true;
    }

    false
}

/// Sucht die Modul-Datei im `modules/` Ordner (neben der Binary).
fn find_module_file(name: &str) -> Option<String> {
    let candidates = vec![
        // Neben der Binary
        modules_dir().join(format!("{name}.dylib")),
        modules_dir().join(format!("{name}.so")),
        modules_dir().join(format!("{name}.dll")),
        // In stone_data/modules
        stone_modules_dir().join(format!("{name}.dylib")),
        stone_modules_dir().join(format!("{name}.so")),
    ];

    for path in &candidates {
        if path.exists() {
            return Some(path.to_string_lossy().to_string());
        }
    }
    None
}

// ─── Pfade ───────────────────────────────────────────────────────────────────

/// Ordner für Module neben der Binary.
fn modules_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("modules")
}

/// Ordner für Module in stone_data.
fn stone_modules_dir() -> PathBuf {
    dirs_next().join("modules")
}

/// Plattform-spezifisches Datenverzeichnis.
pub fn dirs_next() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join("Library/Application Support/stone-dashboard")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/share/stone-dashboard")
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        PathBuf::from(appdata).join("stone-dashboard")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("./stone_data")
    }
}

// ─── Tauri Commands ──────────────────────────────────────────────────────────

/// Gibt alle verfügbaren Module zurück (Core + Optional).
#[tauri::command]
pub fn get_modules() -> Vec<ModuleInfo> {
    let mut all = get_core_modules();
    all.extend(get_optional_modules());
    all
}

/// Prüft ob ein bestimmtes Modul verfügbar ist.
#[tauri::command]
pub fn is_module_available_cmd(name: String) -> bool {
    match name.as_str() {
        "messenger" | "wallet" | "explorer" | "node-manager" => true,
        _ => is_module_available(&name),
    }
}

// ─── Plugin-Loader (libloading) ──────────────────────────────────────────────

/// Lädt ein optionales Modul zur Laufzeit.
///
/// # Safety
///
/// Lädt natives Code aus einer externen Datei.
/// Nur signierte Module von vertrauenswürdigen Quellen laden!
pub unsafe fn load_module(name: &str) -> Result<libloading::Library, String> {
    let path = find_module_file(name)
        .ok_or_else(|| format!("Modul '{name}' nicht gefunden"))?;

    // TODO: Signatur-Prüfung vor dem Laden
    // verify_module_signature(&path)?;

    unsafe {
        libloading::Library::new(&path)
            .map_err(|e| format!("Konnte Modul '{name}' nicht laden: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_modules_always_available() {
        let core = get_core_modules();
        assert_eq!(core.len(), 4);
        for m in &core {
            assert!(m.available);
            assert!(m.built_in);
        }
    }

    #[test]
    fn test_optional_modules_list() {
        let opt = get_optional_modules();
        assert_eq!(opt.len(), 2);
        assert_eq!(opt[0].name, "gaming");
        assert_eq!(opt[1].name, "node");
    }
}
