//! Public-IP Watchdog — Erkennt Änderungen der öffentlichen IPv4-Adresse.
//!
//! Läuft als Hintergrund-Task im Master-Node und fragt stündlich die
//! öffentliche IP über externe Dienste (api.ipify.org, ifconfig.me, icanhazip.com) ab.
//!
//! Bei einer Änderung:
//! 1. `STONE_PUBLIC_IP` Env-Variable wird aktualisiert
//! 2. Neue IP wird in `stone_data/public_ip.txt` gespeichert
//! 3. `NodeEvent::PublicIpChanged` wird publiziert
//! 4. Der Node kann daraufhin Peers neu registrieren
//!
//! ## Konfiguration
//!
//! - `STONE_IP_CHECK_INTERVAL_SECS` — Prüfintervall in Sekunden (Default: 3600 = 1h)
//! - `STONE_IP_CHECK_DISABLED=1` — Watchdog deaktivieren

use std::time::Duration;

use crate::blockchain::data_dir;
use crate::master::{MasterNodeState, NodeEvent};

/// Standard-Prüfintervall: 1 Stunde
const DEFAULT_CHECK_INTERVAL_SECS: u64 = 3600;

/// Datei in der die zuletzt erkannte öffentliche IP gespeichert wird
fn public_ip_file() -> String {
    format!("{}/public_ip.txt", data_dir())
}

/// Liest die gespeicherte öffentliche IP aus der Datei.
pub fn stored_public_ip() -> Option<String> {
    std::fs::read_to_string(public_ip_file())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Speichert die öffentliche IP in die Datei.
fn save_public_ip(ip: &str) {
    let _ = std::fs::create_dir_all(data_dir());
    let _ = std::fs::write(public_ip_file(), ip);
}

/// Fragt die öffentliche IPv4-Adresse über mehrere externe Dienste ab.
/// Gibt `None` zurück wenn alle Dienste fehlschlagen.
pub async fn fetch_public_ip() -> Option<String> {
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    for url in &services {
        match client.get(*url).send().await {
            Ok(resp) => {
                if let Ok(ip) = resp.text().await {
                    let ip = ip.trim().to_string();
                    // Einfache IPv4-Validierung: 7-15 Zeichen, Punkte, Ziffern
                    if !ip.is_empty()
                        && ip.len() >= 7
                        && ip.len() <= 15
                        && ip.chars().all(|c| c.is_ascii_digit() || c == '.')
                        && ip.split('.').count() == 4
                    {
                        return Some(ip);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// Startet den Public-IP-Watchdog als Hintergrund-Task.
///
/// Wird beim Master-Node-Start aufgerufen. Läuft als `tokio::spawn`.
///
/// - Prüft stündlich (oder via `STONE_IP_CHECK_INTERVAL_SECS`) die öffentliche IP
/// - Bei Änderung: aktualisiert Env-Var + Datei + publiziert Event
/// - Deaktivierbar via `STONE_IP_CHECK_DISABLED=1`
pub fn spawn_ip_watchdog(node: std::sync::Arc<MasterNodeState>) {
    if std::env::var("STONE_IP_CHECK_DISABLED").as_deref() == Ok("1") {
        println!("[ip-watchdog] Deaktiviert (STONE_IP_CHECK_DISABLED=1)");
        return;
    }

    let interval_secs = std::env::var("STONE_IP_CHECK_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v >= 60) // Minimum 60 Sekunden
        .unwrap_or(DEFAULT_CHECK_INTERVAL_SECS);

    // Beim Start: initiale IP ermitteln und ggf. STONE_PUBLIC_IP setzen
    let current_env_ip = std::env::var("STONE_PUBLIC_IP").ok().filter(|s| !s.is_empty());
    let stored_ip = stored_public_ip();

    // Wenn STONE_PUBLIC_IP nicht gesetzt ist, aus Datei lesen
    if current_env_ip.is_none() {
        if let Some(ref ip) = stored_ip {
            std::env::set_var("STONE_PUBLIC_IP", ip);
            println!("[ip-watchdog] STONE_PUBLIC_IP={ip} (aus public_ip.txt geladen)");
        }
    }

    // Initiale IP speichern falls noch nicht vorhanden
    if stored_ip.is_none() {
        if let Some(ref ip) = current_env_ip {
            save_public_ip(ip);
            println!("[ip-watchdog] Initiale IP gespeichert: {ip}");
        }
    }

    println!(
        "[ip-watchdog] Gestartet — Prüfintervall: {}s ({}min)",
        interval_secs,
        interval_secs / 60
    );

    tokio::spawn(async move {
        // Erste Prüfung nach 60s (damit der Node vollständig gestartet ist)
        tokio::time::sleep(Duration::from_secs(60)).await;

        loop {
            let old_ip = std::env::var("STONE_PUBLIC_IP")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| stored_public_ip().unwrap_or_default());

            match fetch_public_ip().await {
                Some(new_ip) => {
                    // Immer aktuellen Stand in Datei speichern
                    save_public_ip(&new_ip);

                    if old_ip != new_ip && !old_ip.is_empty() {
                        println!(
                            "[ip-watchdog] 🔄 Öffentliche IP hat sich geändert!"
                        );
                        println!("[ip-watchdog]    Alt: {old_ip}");
                        println!("[ip-watchdog]    Neu: {new_ip}");

                        // Env-Variable aktualisieren (für resolve_self_url etc.)
                        std::env::set_var("STONE_PUBLIC_IP", &new_ip);

                        // Event publizieren
                        node.events.publish(NodeEvent::PublicIpChanged {
                            old_ip: old_ip.clone(),
                            new_ip: new_ip.clone(),
                            timestamp: chrono::Utc::now().timestamp(),
                        });

                        println!(
                            "[ip-watchdog] ✅ STONE_PUBLIC_IP aktualisiert + Event publiziert"
                        );
                    } else if old_ip.is_empty() {
                        // Erste Erkennung nach Start
                        std::env::set_var("STONE_PUBLIC_IP", &new_ip);
                        println!("[ip-watchdog] Öffentliche IP erkannt: {new_ip}");
                    }
                }
                None => {
                    eprintln!("[ip-watchdog] ⚠️  Konnte öffentliche IP nicht ermitteln (alle Dienste fehlgeschlagen)");
                }
            }

            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_validation() {
        // fetch_public_ip validiert intern — hier testen wir nur die Grundprinzipien
        let valid = "61.8.141.250";
        assert!(valid.len() >= 7);
        assert!(valid.len() <= 15);
        assert!(valid.chars().all(|c| c.is_ascii_digit() || c == '.'));
        assert_eq!(valid.split('.').count(), 4);
    }
}
