//! Embedded Stone Node Manager
//!
//! Manages a local stone-master process. Before launching, we automatically
//! ensure the binary is executable and strip the macOS quarantine attribute.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub enabled: bool,
    pub port: u16,
    /// Mining throttle 0–100%. Passed as MINING_THROTTLE_PCT to stone-master.
    pub cpu_pct: u8,
    /// Explicit path to stone-master binary. Empty = auto-detect.
    pub binary_path: String,
    /// libp2p multiaddresses, comma-separated.
    pub seed_peers: String,
    /// API-Key for node-to-node sync. Empty = auto-generated.
    #[serde(default)]
    pub api_key: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            enabled: false,
            port: 3080,
            cpu_pct: 25,
            binary_path: String::new(),
            api_key: String::new(),
            seed_peers: "/ip4/212.227.54.241/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd,/ip4/69.48.200.255/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Stopped,
    Starting,
    Running { port: u16, pid: u32 },
    Error { message: String },
    BinaryNotFound,
}

pub struct NodeState {
    pub config: NodeConfig,
    pub status: NodeStatus,
    child: Option<Child>,
    /// Log-Puffer (letzte 500 Zeilen) — für das Terminal in der UI.
    log_lines: Vec<String>,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl NodeState {
    pub fn new() -> Self {
        NodeState {
            config: NodeConfig::default(),
            status: NodeStatus::Stopped,
            child: None,
            log_lines: Vec::new(),
        }
    }

    fn append_log(&mut self, line: &str) {
        self.log_lines.push(line.to_string());
        if self.log_lines.len() > 500 {
            self.log_lines.remove(0);
        }
    }

    pub fn take_logs(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log_lines)
    }

    pub fn peek_logs(&self, count: usize) -> Vec<String> {
        let start = self.log_lines.len().saturating_sub(count);
        self.log_lines[start..].to_vec()
    }
}

pub type SharedNodeState = Arc<Mutex<NodeState>>;

// ── Binary preparation ────────────────────────────────────────────────────────

/// Ensure the binary is executable and not quarantined by macOS Gatekeeper.
/// Returns Err only if we can't set permissions at all.
fn prepare_binary(path: &PathBuf) -> Result<(), String> {
    // 1. Unix: set rwxr-xr-x (0o755) — the common cause of "Permission denied (os error 13)"
    #[cfg(unix)]
    {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("Binary nicht lesbar: {e}"))?;
        let mut perms = meta.permissions();
        let current_mode = perms.mode();
        if current_mode & 0o111 == 0 {
            perms.set_mode(current_mode | 0o755);
            std::fs::set_permissions(path, perms)
                .map_err(|e| format!("Ausführungsrechte konnten nicht gesetzt werden: {e}"))?;
        }
    }
    // Windows: just verify the file exists (no execute-bit concept)
    #[cfg(target_os = "windows")]
    {
        if !path.exists() {
            return Err(format!("Binary nicht gefunden: {}", path.display()));
        }
    }

    // 2. macOS Gatekeeper: remove quarantine extended attribute (if any)
    #[cfg(target_os = "macos")]
    {
        let path_str = path.to_string_lossy().to_string();
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine", &path_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Ok(())
}

// ── Binary discovery ──────────────────────────────────────────────────────────

/// Discover `stone-app-node` (preferred) or `stone-master`.
///
/// Priority:
/// 1. Explicit path from config (`override_path`)
/// 2. `<app_data>/binaries/` — dedicated folder created automatically on first launch
/// 3. Next to our own executable (inside .app bundle on macOS / next to .exe on Windows)
/// 4. Rust build output (`target/release/`) — developer shortcut
/// 5. `$PATH` / `%PATH%` lookup
fn find_binary(app: &AppHandle, override_path: &str) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let exe_suffix = ".exe";
    #[cfg(not(target_os = "windows"))]
    let exe_suffix = "";

    let exe_name = |base: &str| -> String { format!("{}{}", base, exe_suffix) };

    // Ensure the dedicated binaries folder exists
    let _ = app
        .path()
        .app_data_dir()
        .map(|d| {
            let bin_dir = d.join("binaries");
            let _ = std::fs::create_dir_all(&bin_dir);
            bin_dir
        });

    let candidates: Vec<PathBuf> = {
        let mut v = vec![];

        // 0. Explicit override from config
        if !override_path.is_empty() {
            v.push(PathBuf::from(override_path));
        }

        // 1. Dedicated binaries folder — highest default priority
        if let Ok(data_dir) = app.path().app_data_dir() {
            let bin_dir = data_dir.join("binaries");
            v.push(bin_dir.join(exe_name("stone-app-node")));
            v.push(bin_dir.join(exe_name("stone-master")));
            // Also check legacy location (root of app data dir)
            v.push(data_dir.join(exe_name("stone-app-node")));
            v.push(data_dir.join(exe_name("stone-master")));
        }

        // 2. Next to our own executable
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join(exe_name("stone-app-node")));
                v.push(dir.join(exe_name("stone-master")));
            }
        }

        // 3. Project build output (developer shortcut)
        #[cfg(unix)]
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            v.push(home.join("stone-1/target/release/stone-app-node"));
            v.push(home.join("stone-1/target/release/stone-master"));
        }
        #[cfg(target_os = "windows")]
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let profile = PathBuf::from(userprofile);
            v.push(profile.join("stone-1/target/release/stone-app-node.exe"));
            v.push(profile.join("stone-1/target/release/stone-master.exe"));
        }

        // 4. PATH lookup
        for name in &["stone-app-node", "stone-master"] {
            let lookup = exe_name(name);
            #[cfg(unix)]
            {
                if let Ok(out) = Command::new("which").arg(&lookup).output() {
                    if out.status.success() {
                        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        if !p.is_empty() {
                            v.push(PathBuf::from(p));
                        }
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                if let Ok(out) = Command::new("where").arg(&lookup).output() {
                    if out.status.success() {
                        for line in String::from_utf8_lossy(&out.stdout).lines() {
                            let p = line.trim().to_string();
                            if !p.is_empty() {
                                v.push(PathBuf::from(p));
                            }
                        }
                    }
                }
            }
        }

        v
    };

    candidates.into_iter().find(|p| p.exists())
}

// ── node_config.json writer ───────────────────────────────────────────────────

/// Write a minimal node_config.json that stone-master will read on startup.
fn write_node_config(data_dir: &PathBuf, cfg: &NodeConfig) -> Result<(), String> {
    let seed_peers_json: Vec<serde_json::Value> = cfg
        .seed_peers
        .split(',')
        .map(|s| serde_json::Value::String(s.trim().to_string()))
        .filter(|v| !v.as_str().unwrap_or("").is_empty())
        .collect();

    let node_cfg = serde_json::json!({
        "setup_complete": true,
        "node_name": "StoneDesktopNode",
        "wallet_address": "",
        "seed_peers": seed_peers_json,
        "http_port": cfg.port,
        "p2p_port": 4001,
        "data_dir": data_dir.to_string_lossy(),
        "auto_mining_enabled": true,
        "auto_mining_timeout_secs": 120,
        "miner_heartbeat_timeout_secs": 30
    });

    let json = serde_json::to_string_pretty(&node_cfg)
        .map_err(|e| format!("Config-Serialisierung: {e}"))?;
    std::fs::write(data_dir.join("node_config.json"), json)
        .map_err(|e| format!("Config schreiben: {e}"))?;

    Ok(())
}

// ── Tauri commands ────────────────────────────────────────────────────────────

#[tauri::command]
pub fn node_get_logs(state: tauri::State<'_, SharedNodeState>) -> Vec<String> {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let logs = s.take_logs();
    drop(s);
    logs
}

#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    // Finde die lokale LAN-IP (erste non-loopback IPv4)
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("{e}"))?;
    socket.connect("212.227.54.241:3080").map_err(|e| format!("{e}"))?;
    let addr = socket.local_addr().map_err(|e| format!("{e}"))?;
    Ok(addr.ip().to_string())
}

#[tauri::command]
pub fn node_get_status(state: tauri::State<'_, SharedNodeState>) -> NodeStatus {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(child) = &mut s.child {
        match child.try_wait() {
            Ok(Some(exit)) => {
                s.status = NodeStatus::Error {
                    message: format!("Node beendet (exit: {})", exit.code().unwrap_or(-1)),
                };
                s.child = None;
            }
            Ok(None) => {}
            Err(e) => {
                s.status = NodeStatus::Error {
                    message: format!("Status-Fehler: {e}"),
                };
            }
        }
    }
    s.status.clone()
}

#[tauri::command]
pub fn node_get_config(state: tauri::State<'_, SharedNodeState>) -> NodeConfig {
    state.lock().unwrap_or_else(|e| e.into_inner()).config.clone()
}

#[tauri::command]
pub fn node_set_config(
    config: NodeConfig,
    state: tauri::State<'_, SharedNodeState>,
    app: AppHandle,
) -> Result<(), String> {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let was_enabled = s.config.enabled;
    s.config = config.clone();
    drop(s);

    let shared = state.inner().clone();
    persist_config(&app, &config);

    if config.enabled && !was_enabled {
        node_start_internal(&app, &shared)?;
    } else if !config.enabled && was_enabled {
        node_stop_internal(&shared)?;
    }

    Ok(())
}

#[tauri::command]
pub fn node_start(
    state: tauri::State<'_, SharedNodeState>,
    app: AppHandle,
) -> Result<String, String> {
    let shared = state.inner().clone();
    node_start_internal(&app, &shared)
}

#[tauri::command]
pub fn node_stop(state: tauri::State<'_, SharedNodeState>) -> Result<(), String> {
    let shared = state.inner().clone();
    node_stop_internal(&shared)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn kill_process_on_port(port: u16) -> bool {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("lsof")
            .args(["-ti", &format!("tcp:{port}")])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                let pids: Vec<String> = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|l| l.trim().parse::<i32>().ok().map(|p| p.to_string()))
                    .collect();
                let mut killed = false;
                for pid in &pids {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", pid])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    killed = true;
                }
                return killed;
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // netstat -aon | findstr :<port>  →  TCP    0.0.0.0:3080    0.0.0.0:0    LISTENING    12345
        let output = std::process::Command::new("cmd")
            .args(["/c", &format!("netstat -aon | findstr :{}", port)])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut killed = false;
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(pid_str) = parts.last() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            let _ = std::process::Command::new("taskkill")
                                .args(["/PID", &pid.to_string(), "/F"])
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status();
                            killed = true;
                        }
                    }
                }
                return killed;
            }
        }
    }
    false
}

/// Cleanup corrupt RocksDB token_db before Node start.
/// Detects MANIFEST corruption and deletes the entire token_db directory.
fn repair_token_db(data_dir: &PathBuf) {
    let token_db = data_dir.join("token_db");
    if !token_db.exists() {
        return;
    }
    // Check for corrupt MANIFEST files (most common RocksDB failure)
    let manifest_pattern = token_db.join("MANIFEST-*");
    if let Ok(entries) = std::fs::read_dir(&token_db) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("MANIFEST-") {
                // Read first 4 bytes to check for corruption
                if let Ok(data) = std::fs::read(entry.path()) {
                    if data.len() < 4 || data[..4] != [0x53, 0x4b, 0x49, 0x50] {
                        eprintln!("[node-repair] Korrupter MANIFEST in token_db gefunden – lösche DB.");
                        let _ = std::fs::remove_dir_all(&token_db);
                        return;
                    }
                }
            }
        }
    }
}

pub fn node_start_internal(
    app: &AppHandle,
    shared: &SharedNodeState,
) -> Result<String, String> {
    let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());

    if matches!(s.status, NodeStatus::Running { .. }) {
        return Ok(format!("http://127.0.0.1:{}", s.config.port));
    }

    // Kill alle Prozesse die noch auf dem Port lauschen (vom vorherigen Run)
    let port = s.config.port;
    if kill_process_on_port(port) {
        eprintln!("[node] Port {} freigeräumt (alter Prozess gekillt)", port);
        // Kurz warten damit der Port frei wird
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Auto-download node binaries from GitHub if missing locally (first run)
    s.status = NodeStatus::Starting;
    s.append_log("[app] Prüfe Node-Binaries…");
    if let Err(e) = crate::node_binary_downloader::ensure_binaries_available(app) {
        s.status = NodeStatus::Error {
            message: format!("Binary-Download fehlgeschlagen: {e}"),
        };
        return Err(format!(
            "Node-Binaries nicht verfügbar und Download fehlgeschlagen: {e}"
        ));
    }

    // Find binary (prefers stone-app-node, falls back to stone-master)
    let binary = find_binary(app, &s.config.binary_path).ok_or_else(|| {
        s.status = NodeStatus::BinaryNotFound;
        "Node-Binary nicht gefunden. Kein GitHub-Release vorhanden? Erstelle einen Release mit den Binaries.".to_string()
    })?;

    // Automatically fix permissions and remove quarantine — the main fix
    prepare_binary(&binary).map_err(|e| {
        s.status = NodeStatus::Error { message: e.clone() };
        e
    })?;

    s.status = NodeStatus::Starting;
    s.append_log(&format!("[app] Node Start: {} (port={})", binary.display(), port));

    let cpu_pct = s.config.cpu_pct;
    let cfg = s.config.clone();
    drop(s);

    // Prepare data directory
    let data_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("node_data");
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Datenverzeichnis erstellen: {e}"))?;

    // Cleanup corrupt token_db before Node start
    repair_token_db(&data_dir);

    // Write config file (used by stone-master as fallback; stone-app-node reads env vars directly)
    write_node_config(&data_dir, &cfg)?;

    // Build HTTP bootstrap URLs for stone-app-node from the libp2p seed peers field.
    let bootstrap_nodes: String = cfg
        .seed_peers
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.starts_with("http://") || s.starts_with("https://") {
                return Some(s.to_string());
            }
            let parts: Vec<&str> = s.split('/').collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "ip4" {
                    if let Some(ip) = parts.get(i + 1) {
                        return Some(format!("http://{}:{}", ip, port));
                    }
                }
            }
            None
        })
        .collect::<Vec<_>>()
        .join(",");

    let mut cmd = Command::new(&binary);
    cmd.env("STONE_PORT", port.to_string())
        .env("STONE_DATA_DIR", data_dir.to_string_lossy().as_ref())
        .env("STONE_NETWORK", "testnet")
        .env("MINING_THROTTLE_PCT", cpu_pct.to_string())
        .env("STONE_BOOTSTRAP_NODES", &bootstrap_nodes)
        .env("STONE_P2P_DISABLED", "0");
    if !cfg.api_key.is_empty() {
        cmd.env("STONE_CLUSTER_API_KEY", &cfg.api_key);
    }

    // Discord OAuth2 credentials (für POST /api/v1/auth/discord)
    // Die .env wird vom Node aus dem CWD geladen (data_dir), nicht vom Projekt-Root.
    // Deshalb geben wir sie explizit als Umgebungsvariablen mit.
    if let Ok(proj_root_env) = std::env::var("DISCORD_CLIENT_ID") {
        cmd.env("DISCORD_CLIENT_ID", &proj_root_env);
    } else {
        cmd.env("DISCORD_CLIENT_ID", "1504220990484385883");
    }
    if let Ok(proj_root_secret) = std::env::var("DISCORD_CLIENT_SECRET") {
        cmd.env("DISCORD_CLIENT_SECRET", &proj_root_secret);
    } else {
        cmd.env("DISCORD_CLIENT_SECRET", "U8qYqrHUwQpxzm4QH3cMc_O5MYuqDjwq");
    }
    // Analog: NODE_SECRET & NOMAD_URL aus der Projekt-.env an den Node weitergeben
    if let Ok(ns) = std::env::var("NODE_SECRET") {
        cmd.env("NODE_SECRET", &ns);
    }
    if let Ok(nu) = std::env::var("NOMAD_URL") {
        cmd.env("NOMAD_URL", &nu);
    }
    let mut child = cmd
        .current_dir(&data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            let msg = format!("Start fehlgeschlagen: {e}");
            let mut s = shared.lock().unwrap_or_else(|e2| e2.into_inner());
            s.status = NodeStatus::Error { message: msg.clone() };
            msg
        })?;

    let pid = child.id();

    // Spawn log reader threads for stdout/stderr
    {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let shared_out = shared.clone();
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            if let Some(out) = stdout {
                let reader = BufReader::new(out);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        let mut s = shared_out.lock().unwrap_or_else(|e| e.into_inner());
                        s.append_log(&format!("[out] {l}"));
                    }
                }
            }
        });

        let shared_err = shared.clone();
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            if let Some(err) = stderr {
                let reader = BufReader::new(err);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        let mut s = shared_err.lock().unwrap_or_else(|e| e.into_inner());
                        s.append_log(&format!("[err] {l}"));
                    }
                }
            }
        });
    }

    let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
    s.child = Some(child);
    s.status = NodeStatus::Running { port, pid };
    s.append_log(&format!("[app] Node läuft — PID={pid}, Port={port}"));

    Ok(format!("http://127.0.0.1:{}", port))
}

fn node_stop_internal(shared: &SharedNodeState) -> Result<(), String> {
    let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut child) = s.child.take() {
        child.kill().map_err(|e| format!("Konnte nicht stoppen: {e}"))?;
        let _ = child.wait();
    }
    s.status = NodeStatus::Stopped;
    Ok(())
}

fn persist_config(app: &AppHandle, config: &NodeConfig) {
    if let Ok(data_dir) = app.path().app_data_dir() {
        let _ = std::fs::create_dir_all(&data_dir);
        if let Ok(json) = serde_json::to_string_pretty(config) {
            let _ = std::fs::write(data_dir.join("node_config.json"), json);
        }
    }
}

// ── Load persisted config on startup ─────────────────────────────────────────

pub fn load_config(app: &AppHandle) -> NodeConfig {
    if let Ok(data_dir) = app.path().app_data_dir() {
        let cfg_path = data_dir.join("node_config.json");
        if let Ok(data) = std::fs::read_to_string(&cfg_path) {
            if let Ok(cfg) = serde_json::from_str::<NodeConfig>(&data) {
                return cfg;
            }
        }
    }
    NodeConfig::default()
}
