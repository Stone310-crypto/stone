//! App-Logger — Schreibt Startup- und Fehlerlogs in log.txt.
//!
//! Wichtig: Dieser Logger muss OHNE async und OHNE externe Abhängigkeiten
//! funktionieren, da er VOR der Tauri-Runtime initialisiert wird.
//! Er schreibt direkt mit std::fs und flushed nach jedem Eintrag.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static LOGGER: Mutex<Option<AppLogger>> = Mutex::new(None);

struct AppLogger {
    file: File,
    path: PathBuf,
}

/// Initialisiert den Logger. Muss einmal vor der ersten Log-Ausgabe aufgerufen werden.
/// `app_data_dir` ist typischerweise das App-Datenverzeichnis von Tauri.
pub fn init(app_data_dir: &std::path::Path) {
    let log_path = app_data_dir.join("log.txt");
    // Übergeordnetes Verzeichnis erstellen falls nötig
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(file) => {
            let logger = AppLogger { file, path: log_path.clone() };
            if let Ok(mut guard) = LOGGER.lock() {
                *guard = Some(logger);
            }
            // Ersten Eintrag schreiben
            log_raw("══════ Stone Dashboard Log Start ══════");
        }
        Err(e) => {
            // Fallback: stderr
            eprintln!("[log] Konnte log.txt nicht öffnen: {e}");
        }
    }
}

/// Schreibt eine Log-Zeile mit Timestamp.
fn log_raw(msg: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let line = format!("[{ts}] {msg}\n");

    // In Datei schreiben
    if let Ok(mut guard) = LOGGER.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = logger.file.write_all(line.as_bytes());
            let _ = logger.file.flush();
        }
    }
    // stderr nur im Debug-Modus (Windows hat keine Konsole im Release)
    #[cfg(debug_assertions)]
    eprintln!("{msg}");
}

/// Loggt eine Info-Nachricht.
pub fn info(msg: &str) {
    log_raw(&format!("ℹ️  {msg}"));
}

/// Loggt eine Warnung.
pub fn warn(msg: &str) {
    log_raw(&format!("⚠️  {msg}"));
}

/// Loggt einen Fehler.
pub fn error(msg: &str) {
    log_raw(&format!("❌ {msg}"));
}

/// Loggt einen Schritt (für Startup-Tracking).
pub fn step(step_name: &str) {
    log_raw(&format!("▶  {step_name}"));
}

/// Loggt einen erfolgreichen Abschluss eines Schritts.
pub fn done(step_name: &str) {
    log_raw(&format!("✅ {step_name}"));
}

/// Gibt den Pfad zur Log-Datei zurück (falls initialisiert).
pub fn log_path() -> Option<PathBuf> {
    if let Ok(guard) = LOGGER.lock() {
        if let Some(ref logger) = *guard {
            return Some(logger.path.clone());
        }
    }
    None
}

// ─── Panic-Hook ──────────────────────────────────────────────────────────────

/// Installiert einen Panic-Hook der den Panic-Grund in log.txt schreibt.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("PANIC: {info}");
        log_raw(&msg);
        // Auch auf stderr
        eprintln!("{msg}");
    }));
}
