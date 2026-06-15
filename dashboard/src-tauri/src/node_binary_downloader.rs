//! Node Binary Downloader — holt stone-app-node / stone-master von GitHub Releases.
//!
//! Beim ersten Start werden die Binaries automatisch in den `binaries/`-Ordner
//! heruntergeladen und verifiziert. Ein manueller "Update prüfen"-Button in der
//! Node-View triggert `check_for_updates()`, das die lokale Version mit dem
//! neuesten GitHub-Release vergleicht und ggf. herunterlädt.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tauri::AppHandle;

const GITHUB_API: &str = "https://api.github.com/repos/Stone310-crypto/stone/releases/latest";
const BINARY_NAMES: &[&str] = &["stone-app-node", "stone-master"];

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

/// Hält die Versions-Info für eine Binary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryVersion {
    pub tag: String,
    pub sha256: String,
}

/// Lädt die neuesten Release-Informationen von GitHub.
async fn fetch_latest_release(client: &reqwest::Client) -> Result<GitHubRelease> {
    let resp = client
        .get(GITHUB_API)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "StoneDashboard/1.0")
        .send()
        .await
        .context("GitHub-Release-API nicht erreichbar")?;

    let release: GitHubRelease = resp.json().await.context("Ungültige Release-Daten")?;
    Ok(release)
}

/// Ermittelt den Binary-Namen für die aktuelle Plattform.
/// z.B. `stone-app-node-x86_64-pc-windows-msvc.exe`
fn platform_binary_name(base: &str) -> String {
    #[cfg(target_os = "macos")]
    let (os, suffix) = {
        if cfg!(target_arch = "aarch64") {
            ("macos-aarch64", "")
        } else {
            ("macos-x86_64", "")
        }
    };
    #[cfg(target_os = "windows")]
    let (os, suffix) = ("windows-x86_64", ".exe");
    #[cfg(target_os = "linux")]
    let (os, suffix) = ("linux-x86_64", "");

    format!("{}-{}{}", base, os, suffix)
}

/// Lädt eine einzelne Binary herunter und prüft SHA256 gegen die `.sha256`-Datei.
async fn download_binary(
    client: &reqwest::Client,
    assets: &[GitHubAsset],
    base_name: &str,
    dest_dir: &PathBuf,
) -> Result<PathBuf> {
    let binary_name = platform_binary_name(base_name);
    let sha_name = format!("{}.sha256", binary_name);

    // SHA256-Asset finden
    let sha_asset = assets
        .iter()
        .find(|a| a.name == sha_name)
        .with_context(|| format!("Keine SHA256-Datei für {}", binary_name))?;

    let binary_asset = assets
        .iter()
        .find(|a| a.name == binary_name)
        .with_context(|| format!("Kein Binary-Asset: {}", binary_name))?;

    // SHA256 herunterladen
    let expected_sha: String = client
        .get(&sha_asset.browser_download_url)
        .header("Accept", "application/octet-stream")
        .header("User-Agent", "StoneDashboard/1.0")
        .send()
        .await?
        .text()
        .await?
        .trim()
        .to_string();

    // Binary herunterladen
    let bytes = client
        .get(&binary_asset.browser_download_url)
        .header("Accept", "application/octet-stream")
        .header("User-Agent", "StoneDashboard/1.0")
        .send()
        .await?
        .bytes()
        .await?;

    // SHA256 verifizieren
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual_sha = hex::encode(hasher.finalize());

    if actual_sha.to_lowercase() != expected_sha.to_lowercase() {
        anyhow::bail!(
            "SHA256-Prüfung fehlgeschlagen für {}: erwartet {}, erhalten {}",
            binary_name,
            expected_sha,
            actual_sha
        );
    }

    // Speichern — entferne Plattform-Suffix für den finalen Namen
    #[cfg(target_os = "windows")]
    let final_name = format!("{}.exe", base_name);
    #[cfg(not(target_os = "windows"))]
    let final_name = base_name.to_string();

    let dest_path = dest_dir.join(&final_name);
    std::fs::write(&dest_path, &bytes)
        .with_context(|| format!("Binary konnte nicht geschrieben werden: {}", dest_path.display()))?;

    // Ausführbar machen (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dest_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dest_path, perms)?;
    }

    Ok(dest_path)
}

/// Installiert (oder aktualisiert) die Node-Binaries in den `binaries/`-Ordner.
/// Wird beim ersten Start und bei manuellem Update aufgerufen.
pub async fn install_or_update_binaries(app: &AppHandle) -> Result<Vec<(String, PathBuf)>> {
    let data_dir = app
        .path()
        .app_data_dir()
        .context("App-Datenverzeichnis nicht verfügbar")?;
    let dest_dir = data_dir.join("binaries");
    std::fs::create_dir_all(&dest_dir).context("binaries/ Ordner konnte nicht erstellt werden")?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .context("HTTP-Client-Fehler")?;

    let release = fetch_latest_release(&client).await?;

    let mut results = Vec::new();
    for name in BINARY_NAMES {
        match download_binary(&client, &release.assets, name, &dest_dir).await {
            Ok(path) => {
                println!(
                    "[binary-dl] {} heruntergeladen: {} (Release: {})",
                    name,
                    path.display(),
                    release.tag_name
                );
                results.push((name.to_string(), path));
            }
            Err(e) => {
                // Wenn eine Binary fehlt, prüfen wir ob lokal vorhanden
                #[cfg(target_os = "windows")]
                let local = dest_dir.join(format!("{}.exe", name));
                #[cfg(not(target_os = "windows"))]
                let local = dest_dir.join(*name);

                if local.exists() {
                    println!(
                        "[binary-dl] {} konnte nicht aktualisiert werden ({}), nutze lokale Version",
                        name, e
                    );
                    results.push((name.to_string(), local));
                } else {
                    return Err(e.context(format!("Binary {} nicht verfügbar", name)));
                }
            }
        }
    }

    // Version speichern
    let version = BinaryVersion {
        tag: release.tag_name.clone(),
        sha256: String::new(), // nicht relevant für Version-Check
    };
    let version_json =
        serde_json::to_string_pretty(&version).context("Version-Serialisierung fehlgeschlagen")?;
    std::fs::write(dest_dir.join("version.json"), version_json)
        .context("Version-Datei konnte nicht geschrieben werden")?;

    Ok(results)
}

/// Prüft ob ein neueres Release verfügbar ist.
pub async fn check_for_updates(app: &AppHandle) -> Result<Option<String>> {
    let data_dir = app
        .path()
        .app_data_dir()
        .context("App-Datenverzeichnis nicht verfügbar")?;
    let version_path = data_dir.join("binaries").join("version.json");

    let current_tag = if version_path.exists() {
        let data = std::fs::read_to_string(&version_path)?;
        let v: BinaryVersion = serde_json::from_str(&data)?;
        v.tag
    } else {
        String::new()
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let release = fetch_latest_release(&client).await?;

    if release.tag_name != current_tag || current_tag.is_empty() {
        Ok(Some(release.tag_name))
    } else {
        Ok(None)
    }
}