mod file_upload;
mod node_binary_downloader;
mod node_config_db;
mod node_manager;
mod modules;
mod extensions;
mod gaming_proxy;
mod miner_manager;
mod vpn_manager;
mod app_logger;
use tauri::{AppHandle, Manager};
use node_manager::{
    SharedNodeState, NodeState, NodeStatus,
    get_local_ip,
    node_get_logs,
    node_get_status, node_get_config, node_set_config, node_start, node_stop,
    switch_node_network,
    load_config,
    get_node_health,
};
use miner_manager::{
    SharedMinerState, MinerState,
    miner_start, miner_stop, miner_status, miner_set_autostart,
    miner_set_payout_wallet, miner_get_config,
};
use std::sync::{Arc, Mutex};
use serde::Serialize;

#[derive(Serialize, Clone)]
struct SystemStatsResponse {
    system_cpu_pct: f32,
    system_memory_used_mb: u64,
    system_memory_total_mb: u64,
    app_cpu_pct: f32,
    app_memory_mb: u64,
}

#[tauri::command]
fn get_auto_launch() -> Result<bool, String> {
    let app_path = get_auto_launch_path()?;
    let auto = auto_launch::AutoLaunchBuilder::new()
        .set_app_name("Stone Dashboard")
        .set_app_path(&app_path)
        .build()
        .map_err(|e| format!("{e}"))?;
    Ok(auto.is_enabled().unwrap_or(false))
}

#[tauri::command]
fn set_auto_launch(enable: bool) -> Result<bool, String> {
    let app_path = get_auto_launch_path()?;

    let auto = auto_launch::AutoLaunchBuilder::new()
        .set_app_name("Stone Dashboard")
        .set_app_path(&app_path)
        .build()
        .map_err(|e| format!("{e}"))?;

    if enable {
        auto.enable().map_err(|e| format!("{e}"))?;
    } else {
        auto.disable().map_err(|e| format!("{e}"))?;
    }
    Ok(enable)
}

fn get_auto_launch_path() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_str = exe.to_string_lossy().to_string();

    #[cfg(target_os = "macos")]
    {
        // Für macOS: Verwende das .app Bundle wenn wir in einem sind
        let p = std::path::Path::new(&exe_str);
        // Pfad: Stone Dashboard.app/Contents/MacOS/binary
        if let Some(macos_dir) = p.parent() {
            if let Some(contents) = macos_dir.parent() {
                if let Some(bundle) = contents.parent() {
                    if bundle.extension().map(|e| e == "app").unwrap_or(false) {
                        return Ok(bundle.to_string_lossy().to_string());
                    }
                }
            }
        }
        // Fallback: Binary-Pfad (dev mode)
    }
    Ok(exe_str)
}

#[tauri::command]
fn get_system_stats() -> SystemStatsResponse {
    use sysinfo::{System, ProcessesToUpdate};
    let mut sys = System::new_all();
    sys.refresh_all();

    let total_mem = sys.total_memory() / (1024 * 1024);
    let used_mem = sys.used_memory() / (1024 * 1024);

    let cpu = sys.global_cpu_usage() as f32;
    let pid = std::process::id();
    sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid as u32)]), true);
    let process_mem = sys.process(sysinfo::Pid::from_u32(pid as u32))
        .map(|p| p.memory() / (1024 * 1024))
        .unwrap_or(0);
    let process_cpu = sys.process(sysinfo::Pid::from_u32(pid as u32))
        .map(|p| p.cpu_usage() as f32)
        .unwrap_or(0.0);

    SystemStatsResponse {
        system_cpu_pct: cpu,
        system_memory_used_mb: used_mem,
        system_memory_total_mb: total_mem,
        app_cpu_pct: process_cpu,
        app_memory_mb: process_mem,
    }
}

use tauri::WebviewUrl;
use tauri::WebviewWindowBuilder;

#[tauri::command]
fn plugin_open_window(app: tauri::AppHandle, url: String, title: String) -> Result<(), String> {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis();
    let id = format!("plugin-{}", ts);
    WebviewWindowBuilder::new(&app, &id, WebviewUrl::External(url.parse().map_err(|e| format!("Ungültige URL: {e}"))?))
        .title(&title)
        .inner_size(1024.0, 768.0)
        .min_inner_size(400.0, 300.0)
        .resizable(true)
        .visible(true)
        .build()
        .map_err(|e| format!("Fenster konnte nicht erstellt werden: {e}"))?;
    Ok(())
}

/// Validiert eine Datei vor dem Upload (Magic Bytes, Größe, Typ-Prüfung).
#[tauri::command]
fn validate_upload_file(path: String) -> Result<file_upload::ValidationResult, String> {
    file_upload::validate_file(&path).map_err(|e| e.to_string())
}

/// Führt den vollständigen Upload-Prozess durch (Phase 2):
/// 1. Lokale Validierung (Magic Bytes, Größe, Typ)
/// 2. Upload via HTTP multipart an den Stone-Master-Server
/// 3. Server übernimmt Chunking + Erasure-Coding + P2P-Shard-Verteilung
///
/// Parameter:
/// - path: Absoluter Pfad zur Datei
/// - master_url: URL des Stone-Master-Servers (z.B. "http://127.0.0.1:13080")
/// - api_key: API-Key für den Master-Server
/// - session_token: Optionaler Session-Token für Auth
#[tauri::command]
async fn upload_file(
    path: String,
    master_url: String,
    api_key: String,
    session_token: Option<String>,
) -> Result<file_upload::UploadResult, String> {
    file_upload::process_upload(
        &path,
        &master_url,
        &api_key,
        session_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Gibt den von der Magic-Byte-Engine erkannten Dateityp zurück (nur Analyse).
#[tauri::command]
fn detect_file_type_cmd(path: String) -> Result<Option<file_upload::MagicByteInfo>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 256];
    let n = f.read(&mut buf).map_err(|e| e.to_string())?;
    buf.truncate(n);
    Ok(file_upload::detect_file_type(&buf))
}

// ─── VPN-Status (via Node HTTP API, kein separater Prozess) ─────────────

/// VPN-Status vom lokalen Node abrufen (GET /api/v1/vpn/status).
#[tauri::command]
async fn dashboard_vpn_status(node_state: tauri::State<'_, SharedNodeState>) -> Result<vpn_manager::VpnStatusResponse, String> {
    let port = {
        let s = node_state.lock().unwrap_or_else(|e| e.into_inner());
        s.config.port
    };
    vpn_manager::fetch_vpn_status(port).await
}

/// VPN-ID rotieren (POST /api/v1/vpn/rotate).
#[tauri::command]
async fn dashboard_vpn_rotate(
    node_state: tauri::State<'_, SharedNodeState>,
) -> Result<String, String> {
    let port = {
        let s = node_state.lock().unwrap_or_else(|e| e.into_inner());
        s.config.port
    };
    // Session-Token aus dem Session-Store (falls verfügbar)
    let token = std::env::var("STONE_SESSION_TOKEN").unwrap_or_default();
    vpn_manager::rotate_vpn_id(port, &token).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // ── Logger initialisieren (SO FRÜH WIE MÖGLICH) ──────────────────────
    app_logger::install_panic_hook();
    // Temp-Verzeichnis als Fallback (App-Datenverzeichnis ist noch nicht verfügbar)
    let log_dir = std::env::temp_dir().join("stone-dashboard");
    let _ = std::fs::create_dir_all(&log_dir);
    app_logger::init(&log_dir);
    app_logger::step("App-Start: Logger initialisiert");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            app_logger::step("Setup: Tauri-Plugins geladen, starte Initialisierung...");

            // Modules-Verzeichnis erstellen (für optionale Module)
            let _ = std::fs::create_dir_all(&modules::dirs_next());
            app_logger::done("Verzeichnisse: modules");
            let mods_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("modules")))
                .unwrap_or_else(|| std::path::PathBuf::from("modules"));
            let _ = std::fs::create_dir_all(&mods_dir);

            // Extensions-Verzeichnis erstellen
            let _ = std::fs::create_dir_all(&extensions::extensions_dir());
            app_logger::done("Verzeichnisse: extensions");

            // Logger auf das richtige App-Datenverzeichnis umleiten
            if let Ok(data_dir) = app.path().app_data_dir() {
                app_logger::init(&data_dir);
                app_logger::info(&format!("App-Datenverzeichnis: {}", data_dir.display()));
            }

            // Bundled Extensions aus den App-Ressourcen extrahieren (Production-Build)
            app_logger::step("Extrahiere Bundled Extensions...");
            extract_bundled_extensions(app.handle());
            app_logger::done("Bundled Extensions extrahiert");

            app_logger::step("Lade Node-Konfiguration...");
            let mut cfg = load_config(app.handle());
            // Immer Mainnet/3180 als Standard – kein automatischer Testnet-Start
            cfg.network = "mainnet".to_string();
            cfg.port = 3180;
            app_logger::done(&format!("Node-Konfiguration geladen (Port={}, Netzwerk={})", cfg.port, cfg.network));
            let enabled = cfg.enabled;
            let mut state = NodeState::new();
            state.config = cfg;
            let shared: SharedNodeState = Arc::new(Mutex::new(state));

            // Auto-download node binaries on startup (always checks for updates).
            // Node startet erst NACHDEM die Binaries bereit sind.
            let app_handle_dl = app.handle().clone();
            let shared_clone = shared.clone();
            let enabled_clone = enabled;
            tauri::async_runtime::spawn(async move {
                app_logger::step("Background: Warte 1s, dann Node-Binary-Check...");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                app_logger::step("Background: Prüfe/Installiere Node-Binaries...");
                match node_binary_downloader::install_or_update_binaries(&app_handle_dl).await {
                    Ok((_binaries, updated)) => {
                        app_logger::done(&format!("Node-Binaries bereit (updated={})", updated));
                        if updated {
                            app_logger::info("Node-Binaries wurden aktualisiert.");
                            let running = {
                                let state = shared_clone.lock().unwrap_or_else(|e| e.into_inner());
                                matches!(state.status, NodeStatus::Running { .. })
                            };
                            if running {
                                app_logger::info("Node läuft – starte neu für Binary-Update…");
                                let _ = node_manager::node_stop_internal(&shared_clone);
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                let _ = node_manager::node_start_internal(&app_handle_dl, &shared_clone);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        app_logger::error(&format!("Node-Binary-Check fehlgeschlagen: {e}"));
                    }
                }
                // Node starten falls enabled und noch nicht gestartet
                if enabled_clone {
                    let running = {
                        let s = shared_clone.lock().unwrap_or_else(|e| e.into_inner());
                        matches!(s.status, NodeStatus::Running { .. })
                    };
                    if !running {
                        app_logger::step("Background: Starte Node...");
                        // catch_unwind um Panic zu loggen statt lautlos zu crashen
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            node_manager::node_start_internal(&app_handle_dl, &shared_clone)
                        }));
                        match result {
                            Ok(Ok(url)) => app_logger::done(&format!("Node gestartet: {url}")),
                            Ok(Err(e)) => app_logger::error(&format!("Node-Start fehlgeschlagen: {e}")),
                            Err(panic_info) => {
                                let msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                                    s.clone()
                                } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                                    s.to_string()
                                } else {
                                    "Unbekannte Panic".to_string()
                                };
                                app_logger::error(&format!("PANIC beim Node-Start: {msg}"));
                            }
                        }
                    }
                }
            });

            app.manage(shared);
            app_logger::done("SharedNodeState registriert");

            // Miner state
            let miner_state = MinerState::new();
            let shared_miner: SharedMinerState = Arc::new(Mutex::new(miner_state));
            app.manage(shared_miner);
            app_logger::done("MinerState registriert");

            app_logger::step("Setup abgeschlossen — App bereit");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_local_ip,
            node_get_logs,
            node_get_status,
            node_get_config,
            node_set_config,
            node_start,
            node_stop,
            switch_node_network,
            get_node_health,
            dashboard_vpn_status,
            dashboard_vpn_rotate,
            plugin_open_window,
            validate_upload_file,
            upload_file,
            detect_file_type_cmd,
            node_binary_check_updates,
            node_binary_download_latest,
            get_system_stats,
            get_auto_launch,
            set_auto_launch,
            modules::get_modules,
            modules::is_module_available_cmd,
            extensions::get_installed_extensions,
            extensions::get_available_extensions,
            extensions::cmd_install_extension,
            extensions::cmd_uninstall_extension,
            extensions::rate_extension,
            extensions::get_my_rating,
            extensions::check_for_updates,
            extensions::get_extension_ui,
            extensions::get_theme_css,
            extensions::list_themes,
            extensions::write_theme_css,
            extensions::save_theme_file,
            extensions::list_saved_themes,
            extensions::load_saved_theme,
            extensions::delete_saved_theme,
            extensions::prepare_theme_publish,
            extensions::get_network_status,
            extensions::get_node_config,
            extensions::read_node_config_db,
            gaming_proxy::list_companies,
            gaming_proxy::create_company,
            gaming_proxy::list_games,
            gaming_proxy::register_game,
            gaming_proxy::company_games,
            gaming_proxy::check_game_id,
            miner_start,
            miner_stop,
            miner_status,
            miner_set_autostart,
            miner_set_payout_wallet,
            miner_get_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ── Node Binary Downloader commands ───────────────────────────────────────────

#[tauri::command]
async fn node_binary_check_updates(app: AppHandle) -> Result<Option<String>, String> {
    node_binary_downloader::check_for_updates(&app)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn node_binary_download_latest(
    app: AppHandle,
    node_state: tauri::State<'_, SharedNodeState>,
) -> Result<Vec<(String, String)>, String> {
    let (results, updated) = node_binary_downloader::install_or_update_binaries(&app)
        .await
        .map_err(|e| e.to_string())?;

    // Wenn Binaries aktualisiert wurden und Node läuft → neustarten
    if updated {
        let shared = node_state.inner().clone();
        let running = {
            let state = shared.lock().unwrap_or_else(|e| e.into_inner());
            matches!(state.status, NodeStatus::Running { .. })
        };
        if running {
            eprintln!("[binary-dl] Node läuft – starte neu für Binary-Update…");
            let _ = node_manager::node_stop_internal(&shared);
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            let _ = node_manager::node_start_internal(&app, &shared);
        }
    }

    Ok(results
        .into_iter()
        .map(|(name, path)| (name, path.to_string_lossy().to_string()))
        .collect())
}

// ─── Bundled Extensions (Production Build) ───────────────────────────────────

/// Kopiert gebundelte Extension-Dateien aus dem App-Bundle ins
/// App-Datenverzeichnis, falls sie dort noch nicht existieren.
/// Dadurch funktionieren Dashboard- und Testnet-Extension auch
/// im Production-Build ohne GitHub-Download.
fn extract_bundled_extensions(app: &AppHandle) {
    let Ok(resource_dir) = app.path().resource_dir() else {
        eprintln!("[extensions] Resource-Dir nicht verfügbar – überspringe Bundle-Extraktion");
        return;
    };

    let bundled_ext_dir = resource_dir.join("extensions");
    if !bundled_ext_dir.exists() {
        // Keine gebundelten Extensions (Development-Modus)
        return;
    }

    let target_dir = extensions::extensions_dir();
    let _ = std::fs::create_dir_all(&target_dir);

    // Liste der Extensions die gebundelt sind (werden bei jedem Start
    // überschrieben, damit sie immer der App-Version entsprechen).
    let ext_ids = ["dashboard", "testnet-mode"];
    for id in &ext_ids {
        let src = bundled_ext_dir.join(id);
        if !src.exists() {
            continue;
        }
        let dst = target_dir.join(id);
        // Alte Version löschen, dann neu kopieren
        if dst.exists() {
            let _ = std::fs::remove_dir_all(&dst);
        }
        if let Err(e) = copy_dir_recursive(&src, &dst) {
            eprintln!("[extensions] Konnte '{id}' nicht extrahieren: {e}");
        } else {
            println!("[extensions] 📦 '{id}' aus App-Bundle extrahiert");
        }
    }
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("mkdir: {e}"))?;
    let entries = std::fs::read_dir(src).map_err(|e| format!("read_dir: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("entry: {e}"))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| format!("copy: {e}"))?;
        }
    }
    Ok(())
}
