mod file_upload;
mod node_binary_downloader;
mod node_manager;
mod modules;
mod extensions;
use tauri::{AppHandle, Manager};
use node_manager::{
    SharedNodeState, NodeState,
    get_local_ip,
    node_get_logs,
    node_get_status, node_get_config, node_set_config, node_start, node_stop,
    load_config,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // Modules-Verzeichnis erstellen (für optionale Module)
            let _ = std::fs::create_dir_all(&modules::dirs_next());
            let mods_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("modules")))
                .unwrap_or_else(|| std::path::PathBuf::from("modules"));
            let _ = std::fs::create_dir_all(&mods_dir);

            // Extensions-Verzeichnis erstellen
            let _ = std::fs::create_dir_all(&extensions::extensions_dir());

            let cfg = load_config(app.handle());
            let enabled = cfg.enabled;
            let mut state = NodeState::new();
            state.config = cfg;
            let shared: SharedNodeState = Arc::new(Mutex::new(state));

            // Auto-download node binaries on first start (if missing)
            let app_handle_dl = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // Wait for UI to render
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if let Err(e) = node_binary_downloader::install_or_update_binaries(&app_handle_dl).await {
                    eprintln!("[binary-dl] Initialer Download fehlgeschlagen (falls lokal vorhanden, wird trotzdem gestartet): {e}");
                }
            });

            // Auto-start node if config says so (delayed by 2s to let UI render)
            if enabled {
                let app_handle = app.handle().clone();
                let shared_clone = shared.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let _ = node_manager::node_start_internal(&app_handle, &shared_clone);
                });
            }

            app.manage(shared);
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
async fn node_binary_download_latest(app: AppHandle) -> Result<Vec<(String, String)>, String> {
    let results = node_binary_downloader::install_or_update_binaries(&app)
        .await
        .map_err(|e| e.to_string())?;
    Ok(results
        .into_iter()
        .map(|(name, path)| (name, path.to_string_lossy().to_string()))
        .collect())
}
