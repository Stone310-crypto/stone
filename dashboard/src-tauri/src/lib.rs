mod file_upload;
mod node_manager;
use tauri::Manager;
use node_manager::{
    SharedNodeState, NodeState,
    get_local_ip,
    node_get_logs,
    node_get_status, node_get_config, node_set_config, node_start, node_stop,
    load_config,
};
use std::sync::{Arc, Mutex};

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
        .setup(|app| {
            let cfg = load_config(app.handle());
            let enabled = cfg.enabled;
            let mut state = NodeState::new();
            state.config = cfg;
            let shared: SharedNodeState = Arc::new(Mutex::new(state));

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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
