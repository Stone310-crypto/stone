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
    /// Network mode: "testnet" or "mainnet"
    #[serde(default = "default_network")]
    pub network: String,
}

fn default_network() -> String { "mainnet".into() }

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            enabled: true,
            port: 3180,
            cpu_pct: 25,
            binary_path: String::new(),
            api_key: String::new(),
            network: "mainnet".into(),
            seed_peers: "/ip4/212.227.54.241/tcp/5003/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd,/ip4/69.48.200.255/tcp/5003/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd".to_string(),
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
pub fn find_binary(app: &AppHandle, override_path: &str) -> Option<PathBuf> {
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
            v.push(home.join("stone/target/release/stone-app-node"));
            v.push(home.join("stone/target/release/stone-master"));
        }
        #[cfg(target_os = "windows")]
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let profile = PathBuf::from(userprofile);
            v.push(profile.join("stone/target/release/stone-app-node.exe"));
            v.push(profile.join("stone/target/release/stone-master.exe"));
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

/// Find the stonevpn binary (same priority as find_binary).
pub fn find_vpn_binary(app: &AppHandle) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let exe_suffix = ".exe";
    #[cfg(not(target_os = "windows"))]
    let exe_suffix = "";

    let exe_name = |base: &str| -> String { format!("{}{}", base, exe_suffix) };

    let candidates: Vec<PathBuf> = {
        let mut v = vec![];

        // 1. Dedicated binaries folder
        if let Ok(data_dir) = app.path().app_data_dir() {
            let bin_dir = data_dir.join("binaries");
            v.push(bin_dir.join(exe_name("stonevpn")));
            v.push(data_dir.join(exe_name("stonevpn")));
        }

        // 2. Next to our own executable
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join(exe_name("stonevpn")));
            }
        }

        // 3. Project build output (developer shortcut)
        #[cfg(unix)]
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            v.push(home.join("stone/stone_vpn/target/release/stonevpn"));
        }
        #[cfg(target_os = "windows")]
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let profile = PathBuf::from(userprofile);
            v.push(profile.join("stone/stone_vpn/target/release/stonevpn.exe"));
        }

        // 4. PATH lookup
        let lookup = exe_name("stonevpn");
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

        v
    };

    candidates.into_iter().find(|p| p.exists())
}

// ── node_config.db writer ─────────────────────────────────────────────────────

/// Write config to node_config.db (and node_config.json for backward compat).
fn write_node_config(data_dir: &PathBuf, cfg: &NodeConfig) -> Result<(), String> {
    // Primär: SQLite-DB
    if let Ok(db) = crate::node_config_db::NodeConfigDB::open(data_dir) {
        let _ = db.set("setup_complete", "true");
        let _ = db.set("node_name", "StoneDesktopNode");
        let _ = db.set("wallet_address", "");
        let _ = db.set_u16("http_port", cfg.port);
        let _ = db.set_u16("p2p_port", 5003);
        let _ = db.set("data_dir", &data_dir.to_string_lossy());
        let _ = db.set("auto_mining_enabled", "true");
        let _ = db.set("auto_mining_timeout_secs", "120");
        let _ = db.set("miner_heartbeat_timeout_secs", "30");
        let _ = db.set("api_key", &cfg.api_key);
        let _ = db.set("network", &cfg.network);

        // seed_peers als JSON-Array
        let seed_peers_json: Vec<String> = cfg
            .seed_peers
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let json = serde_json::to_string(&seed_peers_json).map_err(|e| format!("serialize: {e}"))?;
        let _ = db.set("seed_peers", &json);

        // Bootstrap-Nodes
        let net = if cfg.network == "mainnet" { "mainnet" } else { "testnet" };
        let _ = db.replace_bootstrap_nodes(&seed_peers_json, net);
    }

    // Sekundär: JSON (Abwärtskompatibilität)
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
        "p2p_port": 5003,
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
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.peek_logs(200)
}

/// Ruft Blockchain-Netzwerkdaten von der lokalen Node ab.
/// Gibt block_height, peer_count, uptime_secs, mempool_size zurück.
#[derive(Debug, Clone, Serialize)]
pub struct NodeHealthResponse {
    pub block_height: u64,
    pub peer_count: u64,
    pub uptime_secs: u64,
    pub mempool_size: u64,
    pub network: String,
    pub node_id: String,
}

/// VPN-Status für das Dashboard
#[derive(Debug, Clone, Serialize)]
pub struct VpnStatus {
    pub active: bool,
    pub installed: bool,
    pub vpn_ip: Option<String>,
    pub peer_count: u32,
    pub peers: Vec<String>,
    pub mode: String, // "managed" | "service" | "none"
}

/// Prüft ob der stonevpn-Prozess aktuell läuft.
pub fn is_vpn_running() -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("pgrep")
            .args(["-f", "stonevpn"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq stonevpn.exe"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("stonevpn.exe"))
            .unwrap_or(false)
    }
}

/// Prüft ob der VPN-Systemdienst installiert ist.
pub fn is_vpn_service_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::path::Path::new("/Library/LaunchDaemons/com.stone.vpn.plist").exists()
    }
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/etc/systemd/system/stonevpn.service").exists()
    }
    #[cfg(target_os = "windows")]
    {
        false // No system service on Windows yet
    }
}

/// Liest die VPN-IP aus der vpn_ip.txt im stone_data-Verzeichnis.
fn read_vpn_ip(stone_data_dir: &std::path::Path) -> Option<String> {
    let ip_path = stone_data_dir.join("vpn_ip.txt");
    std::fs::read_to_string(&ip_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Liest die Peer-Liste aus vpn_peers.json.
fn read_vpn_peers(stone_data_dir: &std::path::Path) -> Vec<String> {
    let peers_path = stone_data_dir.join("vpn_peers.json");
    if let Ok(data) = std::fs::read_to_string(&peers_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
            return json["peers"]
                .as_array()
                .map(|a| a.iter().filter_map(|p| p["vpn_ip"].as_str().map(String::from)).collect())
                .unwrap_or_default();
        }
    }
    vec![]
}

fn vpn_data_dir(app: &AppHandle) -> std::path::PathBuf {
    app.path().app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("vpn_data")
}

#[tauri::command]
pub fn get_vpn_status(app: AppHandle) -> VpnStatus {
    let running = is_vpn_running();
    let installed = is_vpn_service_installed();
    let data_dir = vpn_data_dir(&app);
    let vpn_ip = read_vpn_ip(&data_dir);
    let peers = read_vpn_peers(&data_dir);

    let mode = if running && installed { "service" }
        else if running { "managed" }
        else { "none" };

    VpnStatus {
        active: running,
        installed,
        vpn_ip,
        peer_count: peers.len() as u32,
        peers,
        mode: mode.to_string(),
    }
}

/// Startet stonevpn direkt (nicht als Systemdienst).
/// Der VPN läuft solange, bis die App ihn stoppt oder beendet wird.
#[tauri::command]
pub fn start_vpn(app: AppHandle) -> Result<String, String> {
    // Prüfe ob bereits ein VPN läuft
    if is_vpn_running() {
        // Bereits aktiv — IP auslesen
        let ip = read_vpn_ip(&vpn_data_dir(&app)).unwrap_or_else(|| "?".to_string());
        return Ok(format!("VPN läuft bereits (IP: {ip})"));
    }

    let vpn_binary = find_vpn_binary(&app)
        .ok_or_else(|| "stonevpn-Binary nicht gefunden. Bitte warte auf das nächste GitHub-Release.".to_string())?;
    prepare_binary(&vpn_binary)?;

    let vpn_path = vpn_binary.to_string_lossy().to_string();
    let vpn_port = "51821";
    let vpn_relays = "212.227.54.241:51821";
    let data_dir = vpn_data_dir(&app);
    let _ = std::fs::create_dir_all(&data_dir);
    let data_str = data_dir.to_string_lossy().to_string();
    let log_path = data_dir.join("stonevpn.log");

    let log_file = std::fs::File::create(&log_path)
        .map_err(|e| format!("Log-Datei: {e}"))?;

    #[cfg(target_os = "macos")]
    {
        // macOS: TUN via osascript mit Admin-Rechten, stderr in Log-Datei
        let script = format!(
            "do shell script \"'{}' --tun --port {} --relays '{}' --stone-data '{}' >> '{}' 2>&1 &\" with administrator privileges",
            vpn_path.replace('\'', "'\\''"),
            vpn_port,
            vpn_relays,
            data_str.replace('\'', "'\\''"),
            log_path.to_string_lossy().replace('\'', "'\\''"),
        );
        let mut child = std::process::Command::new("osascript")
            .args(["-e", &script])
            .spawn()
            .map_err(|e| format!("osascript fehlgeschlagen: {e}"))?;
        let pid = child.id();
        std::thread::spawn(move || { let _ = child.wait(); });

        // Warte auf VPN-IP (max 15s)
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(15) {
            if let Some(ip) = read_vpn_ip(&data_dir) {
                return Ok(format!("VPN gestartet — IP: {ip} (PID≈{pid})"));
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Ok(format!("VPN wird gestartet… (PID≈{pid}, warte auf IP)"))
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Linux/Windows: Starte direkt (TUN braucht root, fallback: ohne --tun)
        let mut cmd = std::process::Command::new(&vpn_path);
        cmd.arg("--tun")
            .arg("--port").arg(vpn_port)
            .arg("--relays").arg(vpn_relays)
            .arg("--stone-data").arg(&data_str)
            .stdout(log_file.try_clone().map_err(|e| format!("{e}"))?)
            .stderr(log_file);

        let child = cmd.spawn()
            .map_err(|e| format!("Start fehlgeschlagen: {e}\n\n💡 Tipp: Starte die App als Administrator, damit TUN-Devices erstellt werden können."))?;

        let pid = child.id();
        std::thread::spawn(move || { let _ = child.wait(); });

        // Warte auf VPN-IP
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(15) {
            if let Some(ip) = read_vpn_ip(&data_dir) {
                return Ok(format!("VPN gestartet — IP: {ip} (PID={pid})"));
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Ok(format!("VPN gestartet — PID={pid} (warte auf IP-Zuweisung…)"))
    }
}

/// Stoppt alle laufenden stonevpn-Prozesse.
#[tauri::command]
pub fn stop_vpn() -> Result<String, String> {
    if !is_vpn_running() {
        return Ok("VPN läuft nicht.".to_string());
    }

    #[cfg(unix)]
    {
        let output = std::process::Command::new("pkill")
            .args(["-f", "stonevpn"])
            .output()
            .map_err(|e| format!("pkill fehlgeschlagen: {e}"))?;
        if output.status.success() {
            Ok("VPN gestoppt.".to_string())
        } else {
            // Versuche mit sudo
            std::process::Command::new("sudo")
                .args(["-n", "pkill", "-f", "stonevpn"])
                .status()
                .map_err(|_| "Konnte VPN nicht stoppen — läuft er als Systemdienst? Nutze 'VPN-Dienst stoppen'.".to_string())?;
            Ok("VPN gestoppt (via sudo).".to_string())
        }
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("taskkill")
            .args(["/F", "/IM", "stonevpn.exe"])
            .status()
            .map_err(|e| format!("taskkill fehlgeschlagen: {e}"))?;
        Ok("VPN gestoppt.".to_string())
    }
}

/// Installiert stonevpn als Systemdienst (LaunchDaemon / systemd).
#[tauri::command]
pub fn install_vpn_service(app: AppHandle) -> Result<String, String> {
    let vpn_binary = find_vpn_binary(&app)
        .ok_or_else(|| "stonevpn-Binary nicht gefunden.".to_string())?;
    prepare_binary(&vpn_binary)?;

    let vpn_path = vpn_binary.to_string_lossy().to_string();
    let vpn_port = "51821";
    let vpn_relays = "212.227.54.241:51821";
    let data_dir = vpn_data_dir(&app);
    let _ = std::fs::create_dir_all(&data_dir);
    let data_str = data_dir.to_string_lossy().to_string();

    #[cfg(target_os = "macos")]
    {
        let plist_path = "/Library/LaunchDaemons/com.stone.vpn.plist";
        let log_str = data_dir.join("stonevpn.log").to_string_lossy().to_string();
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.stone.vpn</string>
    <key>ProgramArguments</key>
    <array>
        <string>{vpn_path}</string>
        <string>--tun</string>
        <string>--port</string>
        <string>{vpn_port}</string>
        <string>--relays</string>
        <string>{vpn_relays}</string>
        <string>--stone-data</string>
        <string>{data_str}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_str}</string>
    <key>StandardErrorPath</key>
    <string>{log_str}</string>
</dict>
</plist>"#
        );
        let esc = |s: &str| s.replace('\\', "\\\\").replace('\'', "'\\''");
        let script = format!(
            "do shell script \"mkdir -p '{}' && cat > '{}' << 'PLISTEOF'\n{}\nPLISTEOF\nlaunchctl unload '{}' 2>/dev/null; launchctl load '{}'\" with administrator privileges",
            esc(&data_str), esc(plist_path), plist_content, esc(plist_path), esc(plist_path),
        );
        let output = std::process::Command::new("osascript")
            .args(["-e", &script]).output()
            .map_err(|e| format!("osascript: {e}"))?;
        if output.status.success() {
            Ok(format!("✅ VPN-Dienst installiert & gestartet\n📄 {plist_path}"))
        } else {
            Err(format!("❌ {}\n\n💡 Admin-Passwort benötigt.", String::from_utf8_lossy(&output.stderr).trim()))
        }
    }

    #[cfg(target_os = "linux")]
    {
        let sp = "/etc/systemd/system/stonevpn.service";
        let content = format!(
            "[Unit]\nDescription=Stone VPN\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={vpn_path} --tun --port {vpn_port} --relays {vpn_relays} --stone-data {data_str}\nRestart=on-failure\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target");
        let script = format!("mkdir -p '{}' && cat > '{}' << 'EOF'\n{}\nEOF\nsystemctl daemon-reload && systemctl enable stonevpn && systemctl start stonevpn", data_str, sp, content);
        let output = std::process::Command::new("sudo").args(["-n", "bash", "-c", &script]).output()
            .map_err(|_| "sudo nötig — bitte als root ausführen.".to_string())?;
        if output.status.success() { Ok(format!("✅ Dienst installiert: {sp}")) }
        else { Err(String::from_utf8_lossy(&output.stderr).trim().to_string()) }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows: direkt starten (kein systemd)
        start_vpn(app)
    }
}

/// Stoppt den VPN-Systemdienst (ohne ihn zu deinstallieren).
#[tauri::command]
pub fn stop_vpn_service() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let plist = "/Library/LaunchDaemons/com.stone.vpn.plist";
        if !std::path::Path::new(plist).exists() {
            return Err("VPN-Dienst ist nicht installiert.".to_string());
        }
        let output = std::process::Command::new("osascript")
            .args(["-e", &format!("do shell script \"launchctl unload '{plist}'\" with administrator privileges")])
            .output()
            .map_err(|e| format!("osascript: {e}"))?;
        if output.status.success() { Ok("VPN-Dienst gestoppt.".to_string()) }
        else { Err(String::from_utf8_lossy(&output.stderr).trim().to_string()) }
    }
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("sudo")
            .args(["-n", "systemctl", "stop", "stonevpn"])
            .output()
            .map_err(|_| "sudo nötig.".to_string())?;
        if output.status.success() { Ok("VPN-Dienst gestoppt.".to_string()) }
        else { Err(String::from_utf8_lossy(&output.stderr).trim().to_string()) }
    }
    #[cfg(target_os = "windows")]
    {
        stop_vpn()
    }
}

/// Deinstalliert den VPN-Systemdienst vollständig.
#[tauri::command]
pub fn uninstall_vpn_service() -> Result<String, String> {
    // Erst stoppen
    let _ = stop_vpn_service();

    #[cfg(target_os = "macos")]
    {
        let plist = "/Library/LaunchDaemons/com.stone.vpn.plist";
        let output = std::process::Command::new("osascript")
            .args(["-e", &format!("do shell script \"rm -f '{plist}'\" with administrator privileges")])
            .output()
            .map_err(|e| format!("osascript: {e}"))?;
        if output.status.success() { Ok("✅ VPN-Dienst deinstalliert.".to_string()) }
        else { Err(String::from_utf8_lossy(&output.stderr).trim().to_string()) }
    }
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("sudo")
            .args(["-n", "bash", "-c", "systemctl disable stonevpn 2>/dev/null; rm -f /etc/systemd/system/stonevpn.service; systemctl daemon-reload"])
            .output()
            .map_err(|_| "sudo nötig.".to_string())?;
        if output.status.success() { Ok("✅ VPN-Dienst deinstalliert.".to_string()) }
        else { Err(String::from_utf8_lossy(&output.stderr).trim().to_string()) }
    }
    #[cfg(target_os = "windows")]
    {
        stop_vpn()
    }
}

#[tauri::command]
pub async fn get_node_health(
    state: tauri::State<'_, SharedNodeState>,
) -> Result<NodeHealthResponse, String> {
    let cfg = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.config.clone()
    };
    let base_url = format!("http://127.0.0.1:{}", cfg.port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Client-Fehler: {e}"))?;

    let health: serde_json::Value = client
        .get(format!("{}/api/v1/health", base_url))
        .send()
        .await
        .map_err(|e| format!("Node nicht erreichbar: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Health-Parse: {e}"))?;

    // /api/v1/status liefert NodeStatusResponse:
    //   { node_id, role, chain: { block_height, .. }, metrics: { mempool_size, .. },
    //     peers: [...], started_at: <unix-timestamp>, trust: {..} }
    let status: serde_json::Value = client
        .get(format!("{}/api/v1/status", base_url))
        .send()
        .await
        .map_err(|e| format!("Status nicht erreichbar: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Status-Parse: {e}"))?;

    let peer_count = status["peers"]
        .as_array()
        .map(|a| a.len() as u64)
        .unwrap_or(0);

    let started_at = status["started_at"].as_i64().unwrap_or(0);
    let now = chrono::Utc::now().timestamp();
    let uptime_secs = if started_at > 0 && now > started_at {
        (now - started_at) as u64
    } else {
        0
    };

    let mempool_size = status["metrics"]["mempool_size"]
        .as_u64()
        .or_else(|| status["mempool_size"].as_u64())
        .unwrap_or(0);

    Ok(NodeHealthResponse {
        block_height: health["block_height"].as_u64().unwrap_or(0),
        node_id: health["node_id"].as_str().unwrap_or("?").to_string(),
        network: health["network"].as_str().unwrap_or("?").to_string(),
        peer_count,
        uptime_secs,
        mempool_size,
    })
}

#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    // Finde die lokale LAN-IP (erste non-loopback IPv4)
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("{e}"))?;
    socket.connect("212.227.54.241:3180").map_err(|e| format!("{e}"))?;
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

/// Restart the node with a different network (testnet ↔ mainnet).
/// Stops the current process and restarts with the opposite network.
/// The new port is auto-determined: 3080 for testnet, 3180 for mainnet.
#[tauri::command]
pub fn switch_node_network(
    state: tauri::State<'_, SharedNodeState>,
    app: AppHandle,
) -> Result<String, String> {
    let current_network;
    let _cpu_pct;
    {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        current_network = s.config.network.clone();
        _cpu_pct = s.config.cpu_pct;
    }

    // Toggle network
    let new_network = if current_network == "mainnet" { "testnet" } else { "mainnet" };
    let new_port: u16 = if new_network == "mainnet" { 3180 } else { 3080 };

    // Stop current node
    node_stop_internal(&state.inner().clone())?;

    // Wait for port to be released
    std::thread::sleep(std::time::Duration::from_millis(800));

    // Update config and persist
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.config.network = new_network.to_string();
        s.config.port = new_port;
    }
    persist_config(&app, &state.lock().unwrap_or_else(|e| e.into_inner()).config.clone());

    // Kill anything still on the new port
    kill_process_on_port(new_port);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Start with new network
    let url = node_start_internal(&app, &state.inner().clone())?;

    Ok(format!("{}|{}", new_network, url))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

#[allow(unused_variables)]
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
    let _manifest_pattern = token_db.join("MANIFEST-*");
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

    // Prepare data directory (network-specific: node_data_testnet / node_data_mainnet)
    let data_dir_name = if cfg.network == "mainnet" { "node_data_mainnet" } else { "node_data_testnet" };
    let data_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(data_dir_name);
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
        .env("STONE_NETWORK", cfg.network.as_str())
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

    // ── VPN Hinweis ────────────────────────────────────────────────────
    // Der VPN läuft als SYSTEM-DIENST (LaunchDaemon / systemd), nicht als
    // Teil der App. Das vermeidet Permission-Probleme mit TUN-Devices.
    // Über "VPN Service installieren" im Dashboard kann er eingerichtet werden.
    if find_vpn_binary(app).is_some() {
        s.append_log("[vpn] stonevpn-Binary gefunden.");
        s.append_log("[vpn] 💡 VPN kann als Systemdienst installiert werden (Dashboard → Node → VPN Service).");
    } else {
        s.append_log("[vpn] ⚠️ stonevpn-Binary nicht gefunden.");
        s.append_log("[vpn] 💡 Beim nächsten GitHub-Release wird stonevpn mit heruntergeladen.");
    }

    drop(s);

    Ok(format!("http://127.0.0.1:{}", port))
}

pub fn node_stop_internal(shared: &SharedNodeState) -> Result<(), String> {
    let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut child) = s.child.take() {
        child.kill().map_err(|e| format!("Konnte nicht stoppen: {e}"))?;
        let _ = child.wait();
    }
    // Note: VPN ist ein Systemdienst und wird hier NICHT beendet.
    s.status = NodeStatus::Stopped;
    Ok(())
}

fn persist_config(app: &AppHandle, config: &NodeConfig) {
    if let Ok(data_dir) = app.path().app_data_dir() {
        let _ = std::fs::create_dir_all(&data_dir);

        // Primär: SQLite-DB (node_config.db)
        if let Ok(db) = crate::node_config_db::NodeConfigDB::open(&data_dir) {
            let _ = db.set("enabled", if config.enabled { "true" } else { "false" });
            let _ = db.set_u16("http_port", config.port);
            let _ = db.set("cpu_pct", &config.cpu_pct.to_string());
            let _ = db.set("seed_peers", &config.seed_peers);
            let _ = db.set("api_key", &config.api_key);
            let _ = db.set("network", &config.network);

            // Bootstrap-Nodes aus seed_peers extrahieren
            let net = if config.network == "mainnet" { "mainnet" } else { "testnet" };
            let peers: Vec<String> = config.seed_peers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let _ = db.replace_bootstrap_nodes(&peers, net);

            // Migration von node_config.json (einmalig)
            db.migrate_json_if_needed(&data_dir);
        }

        // Sekundär: JSON (Abwärtskompatibilität)
        if let Ok(json) = serde_json::to_string_pretty(config) {
            let _ = std::fs::write(data_dir.join("node_config.json"), json);
        }
    }
}

// ── Load persisted config on startup ─────────────────────────────────────────

pub fn load_config(app: &AppHandle) -> NodeConfig {
    let default = NodeConfig::default();
    if let Ok(data_dir) = app.path().app_data_dir() {
        let _ = std::fs::create_dir_all(&data_dir);

        // Versuche SQLite-DB (node_config.db)
        if let Ok(db) = crate::node_config_db::NodeConfigDB::open(&data_dir) {
            // Migration von JSON → DB (einmalig)
            db.migrate_json_if_needed(&data_dir);

            let mut cfg = default.clone();
            if let Some(v) = db.get("enabled") { cfg.enabled = v == "true"; }
            if let Some(v) = db.get("http_port") { if let Ok(p) = v.parse() { cfg.port = p; } }
            if let Some(v) = db.get("cpu_pct") { if let Ok(p) = v.parse() { cfg.cpu_pct = p; } }
            if let Some(v) = db.get("binary_path") { cfg.binary_path = v; }
            if let Some(v) = db.get("seed_peers") { cfg.seed_peers = v; }
            if let Some(v) = db.get("api_key") { cfg.api_key = v; }
            if let Some(v) = db.get("network") { cfg.network = v; }
            return cfg;
        }

        // Fallback: node_config.json
        let cfg_path = data_dir.join("node_config.json");
        if let Ok(data) = std::fs::read_to_string(&cfg_path) {
            if let Ok(cfg) = serde_json::from_str::<NodeConfig>(&data) {
                return cfg;
            }
        }
    }
    // First launch — persist default config
    if let Ok(data_dir) = app.path().app_data_dir() {
        let _ = std::fs::create_dir_all(&data_dir);
        if let Ok(db) = crate::node_config_db::NodeConfigDB::open(&data_dir) {
            let _ = db.set("enabled", "true");
            let _ = db.set_u16("http_port", default.port);
            let _ = db.set("cpu_pct", &default.cpu_pct.to_string());
            let _ = db.set("seed_peers", &default.seed_peers);
            let _ = db.set("api_key", &default.api_key);
            let _ = db.set("network", &default.network);
        }
        // Auch JSON für Abwärtskompatibilität
        if let Ok(json) = serde_json::to_string_pretty(&default) {
            let _ = std::fs::write(data_dir.join("node_config.json"), json);
        }
    }
    default
}
