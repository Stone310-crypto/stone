// ─── File Upload & Magic Byte Validation ─────────────────────────────────────
///
/// Drag-and-Drop File Upload für die Stone Dashboard App.
///
/// Phase 1: Magic Byte Validation (serverseitig), Size-Limit, Executable-Block
/// Phase 2: Datei wird via HTTP multipart an den lokalen Stone-Master-Server
///          gesendet, der dann Erasure-Coding + P2P-Shard-Verteilung übernimmt.
///
/// Sicherheitsprinzip: Der Client ist nicht vertrauenswürdig —
/// alle Validierungen werden serverseitig (Tauri Backend) wiederholt,
/// bevor die Datei an den Master-Server weitergeleitet wird.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Maximal erlaubte Datei-Größe in Bytes (100 MB).
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximale Länge der Magic-Byte-Signaturen die wir prüfen.
const MAGIC_MAX_LEN: usize = 256;

// ═══════════════════════════════════════════════════════════════════════════════
// Magic Byte Detection
// ═══════════════════════════════════════════════════════════════════════════════

/// Repräsentiert das Ergebnis der Magic-Byte-Analyse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicByteInfo {
    pub mime_type: String,
    pub description: String,
    pub is_executable: bool,
    pub is_archive: bool,
}

/// Prüft die ersten Bytes einer Datei gegen bekannte Magic-Byte-Signaturen.
///
/// Gibt `MagicByteInfo` zurück, oder `None` wenn der Typ unbekannt ist
/// (dann wird die Datei als generischer Binary-Typ behandelt).
pub fn detect_file_type(data: &[u8]) -> Option<MagicByteInfo> {
    if data.is_empty() {
        return None;
    }

    let head = |sig: &[u8]| data.len() >= sig.len() && data[..sig.len()] == *sig;

    // ═══ PE (Windows Portable Executable) / EXE / DLL ═══
    if head(b"MZ") {
        if data.len() >= 0x40 {
            let pe_offset = u32::from_le_bytes(
                data[0x3C..0x40].try_into().unwrap_or([0; 4]),
            ) as usize;
            if data.len() > pe_offset + 4 && &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                return Some(MagicByteInfo {
                    mime_type: "application/vnd.microsoft.portable-executable".into(),
                    description: "Windows PE Executable (EXE/DLL/SYS)".into(),
                    is_executable: true,
                    is_archive: false,
                });
            }
        }
        return Some(MagicByteInfo {
            mime_type: "application/x-dosexec".into(),
            description: "MS-DOS / Windows Executable (MZ)".into(),
            is_executable: true,
            is_archive: false,
        });
    }

    // ═══ ELF (Linux Executable) ═══
    if head(b"\x7fELF") {
        let class = if data.len() > 4 { data[4] } else { 0 };
        let desc = match class {
            1 => "ELF 32-bit Executable",
            2 => "ELF 64-bit Executable",
            _ => "ELF Executable",
        };
        return Some(MagicByteInfo {
            mime_type: "application/x-elf".into(),
            description: desc.into(),
            is_executable: true,
            is_archive: false,
        });
    }

    // ═══ Mach-O (macOS Executable) ═══
    if head(b"\xcf\xfa\xed\xfe") || head(b"\xce\xfa\xed\xfe") {
        return Some(MagicByteInfo {
            mime_type: "application/x-mach-binary".into(),
            description: "Mach-O Executable (universal)".into(),
            is_executable: true,
            is_archive: false,
        });
    }

    // ═══ ZIP Archive ═══
    if head(b"PK\x03\x04") || head(b"PK\x05\x06") || head(b"PK\x07\x08") {
        return Some(MagicByteInfo {
            mime_type: "application/zip".into(),
            description: "ZIP Archive".into(),
            is_executable: false,
            is_archive: true,
        });
    }

    // ═══ GZIP Archive ═══
    if head(b"\x1f\x8b") {
        return Some(MagicByteInfo {
            mime_type: "application/gzip".into(),
            description: "GZIP Archive".into(),
            is_executable: false,
            is_archive: true,
        });
    }

    // ═══ TAR Archive ═══
    if data.len() >= 262 && &data[257..262] == b"ustar" {
        return Some(MagicByteInfo {
            mime_type: "application/x-tar".into(),
            description: "TAR Archive".into(),
            is_executable: false,
            is_archive: true,
        });
    }

    // ═══ 7z Archive ═══
    if head(b"7z\xbc\xaf\x27\x1c") {
        return Some(MagicByteInfo {
            mime_type: "application/x-7z-compressed".into(),
            description: "7-Zip Archive".into(),
            is_executable: false,
            is_archive: true,
        });
    }

    // ═══ RAR Archive ═══
    if head(b"Rar!\x1a\x07") || head(b"Rar!\x1a\x07\x01\x00") {
        return Some(MagicByteInfo {
            mime_type: "application/vnd.rar".into(),
            description: "RAR Archive".into(),
            is_executable: false,
            is_archive: true,
        });
    }

    // ═══ PNG ═══
    if head(b"\x89PNG\r\n\x1a\n") {
        return Some(MagicByteInfo {
            mime_type: "image/png".into(),
            description: "PNG Image".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ JPEG ═══
    if head(b"\xff\xd8\xff") {
        return Some(MagicByteInfo {
            mime_type: "image/jpeg".into(),
            description: "JPEG Image".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ GIF ═══
    if head(b"GIF87a") || head(b"GIF89a") {
        return Some(MagicByteInfo {
            mime_type: "image/gif".into(),
            description: "GIF Image".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ WebP ═══
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some(MagicByteInfo {
            mime_type: "image/webp".into(),
            description: "WebP Image".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ BMP ═══
    if head(b"BM") {
        return Some(MagicByteInfo {
            mime_type: "image/bmp".into(),
            description: "BMP Image".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ PDF ═══
    if head(b"%PDF") {
        return Some(MagicByteInfo {
            mime_type: "application/pdf".into(),
            description: "PDF Document".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ MP4 Video ═══
    if head(b"\x00\x00\x00\x18ftypmp42")
        || head(b"\x00\x00\x00\x14ftypisom")
        || head(b"\x00\x00\x00\x1cftypmp42")
        || head(b"\x00\x00\x00\x20ftypmp42")
        || (data.len() >= 12
            && &data[4..8] == b"ftyp"
            && (&data[8..11] == b"mp4" || &data[8..11] == b"isom" || &data[8..11] == b"M4V"))
    {
        return Some(MagicByteInfo {
            mime_type: "video/mp4".into(),
            description: "MP4 Video".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ WebM / MKV ═══
    if head(b"\x1a\x45\xdf\xa3") {
        return Some(MagicByteInfo {
            mime_type: "video/webm".into(),
            description: "WebM / MKV Container".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ MP3 Audio ═══
    if head(b"\xff\xfb") || head(b"\xff\xf3") || head(b"\xff\xf2") || head(b"ID3") {
        return Some(MagicByteInfo {
            mime_type: "audio/mpeg".into(),
            description: "MP3 Audio".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ WAV Audio ═══
    if head(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WAVE" {
        return Some(MagicByteInfo {
            mime_type: "audio/wav".into(),
            description: "WAV Audio".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ FLAC Audio ═══
    if head(b"fLaC") {
        return Some(MagicByteInfo {
            mime_type: "audio/flac".into(),
            description: "FLAC Audio".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ OGG Container ═══
    if head(b"OggS") {
        return Some(MagicByteInfo {
            mime_type: "application/ogg".into(),
            description: "OGG Container (Audio/Video)".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ Plain Text / Source Code ═══
    if is_likely_text(data) {
        return Some(MagicByteInfo {
            mime_type: "text/plain".into(),
            description: "Text File / Source Code".into(),
            is_executable: false,
            is_archive: false,
        });
    }

    // ═══ ISO / Disk Image ═══
    if data.len() >= 0x8001
        && &data[0x8001..0x8001 + 5] == b"CD001"
        && data[0x8000] == 0x01
    {
        return Some(MagicByteInfo {
            mime_type: "application/x-iso9660-image".into(),
            description: "ISO 9660 Disk Image".into(),
            is_executable: false,
            is_archive: true,
        });
    }

    None
}

fn is_likely_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = &data[..data.len().min(512)];
    if sample.is_empty() {
        return false;
    }
    let text_bytes = sample
        .iter()
        .filter(|&&b| {
            b.is_ascii_graphic()
                || b == b' '
                || b == b'\t'
                || b == b'\n'
                || b == b'\r'
        })
        .count();
    let ratio = text_bytes as f64 / sample.len() as f64;
    let starts_like_text = sample.starts_with(b"\xef\xbb\xbf")
        || sample.starts_with(b"#!")
        || sample.starts_with(b"//")
        || sample.starts_with(b"/*")
        || sample.starts_with(b"<!--")
        || sample.starts_with(b"<!DOCTYPE")
        || sample.starts_with(b"<html")
        || sample.starts_with(b"<?xml")
        || sample.starts_with(b"{")
        || sample.starts_with(b"[");
    ratio > 0.90 || starts_like_text
}

// ═══════════════════════════════════════════════════════════════════════════════
// File Validation
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub file_name: String,
    pub file_size: u64,
    pub magic_info: Option<MagicByteInfo>,
    pub error: Option<String>,
    pub sha256_hash: String,
}

pub fn validate_file(path: &str) -> Result<ValidationResult> {
    let file_path = PathBuf::from(path);
    let file_name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    if !file_path.exists() {
        bail!("Datei nicht gefunden: {path}");
    }
    if !file_path.is_file() {
        bail!("Pfad ist keine reguläre Datei: {path}");
    }

    let metadata = fs::metadata(&file_path).context("Datei-Metadaten lesen")?;
    let file_size = metadata.len();

    if file_size > MAX_FILE_SIZE {
        bail!(
            "Datei zu groß: {} MB (Maximum: {} MB)",
            file_size / (1024 * 1024),
            MAX_FILE_SIZE / (1024 * 1024)
        );
    }
    if file_size == 0 {
        bail!("Datei ist leer");
    }

    let mut magic_buf = vec![0u8; MAGIC_MAX_LEN];
    let mut f = fs::File::open(&file_path)?;
    let read_len = f.read(&mut magic_buf)?;
    magic_buf.truncate(read_len);

    let mut hasher = Sha256::new();
    hasher.update(&magic_buf);
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hex::encode(hasher.finalize());

    let magic_info = detect_file_type(&magic_buf);

    if let Some(ref info) = magic_info {
        if info.is_executable {
            bail!(
                "Ausführbare Dateien können nicht direkt hochgeladen werden: {} ({})\n\
                 Tipp: Verpacke die Datei in ein ZIP- oder TAR-Archiv.",
                info.description,
                info.mime_type
            );
        }
    }

    let lower_name = file_name.to_lowercase();
    let blocked_extensions = [
        ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi",
        ".scr", ".pif", ".reg", ".app", ".bin", ".elf", ".so",
        ".dylib", ".sh", ".bash", ".zsh", ".fish",
    ];

    for ext in &blocked_extensions {
        if lower_name.ends_with(ext) {
            bail!(
                "Dateien mit der Endung '{}' können nicht direkt hochgeladen werden.\n\
                 Tipp: Verpacke die Datei in ein ZIP- oder TAR-Archiv.",
                ext
            );
        }
    }

    Ok(ValidationResult {
        valid: true,
        file_name,
        file_size,
        magic_info,
        error: None,
        sha256_hash: hash,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Upload Result (Phase 2: inkl. Server-Antwort)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub success: bool,
    pub file_hash: String,
    pub file_name: String,
    pub file_size: u64,
    pub magic_info: Option<MagicByteInfo>,
    pub error: Option<String>,

    // ── Vom Stone-Master-Server zurück ──────────────────────────────────────
    /// Document-ID (vom Server vergeben)
    pub doc_id: Option<String>,
    /// Block-Index in dem das Dokument gelandet ist
    pub block_index: Option<u64>,
    /// Block-Hash
    pub block_hash: Option<String>,
    /// Version des Dokuments
    pub version: Option<u32>,
    /// Anzahl Chunks
    pub chunk_count: Option<usize>,
    /// Wurde das Dokument verschlüsselt?
    pub encrypted: Option<bool>,
    /// Ist das Dokument signiert?
    pub signed: Option<bool>,
    /// Info falls der Server Shard-Verteilung bestätigt hat
    pub shards_distributed: Option<bool>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 2: Upload an den Stone-Master-Server
// ═══════════════════════════════════════════════════════════════════════════════

/// Sendet die Datei per HTTP POST multipart an den lokalen Stone-Master-Server.
///
/// Der Server (`handle_upload_document`) übernimmt dann:
/// 1. Verschlüsselung (AES-256-GCM)
/// 2. Chunk-Splitting (8 MiB)
/// 3. Erasure-Coding (Reed-Solomon k=4, m=2 → 6 Shards pro Chunk)
/// 4. P2P-Shard-Verteilung (`distribute_shards`)
/// 5. Shard-Holder-Registry-Update
/// 6. Block-Commit + P2P-Broadcast
pub async fn send_to_master_server(
    file_path: &str,
    validation: &ValidationResult,
    master_url: &str,
    api_key: &str,
    session_token: Option<&str>,
) -> Result<serde_json::Value> {
    let file_data = fs::read(file_path).context("Datei für Upload lesen")?;
    let file_name = validation.file_name.clone();

    let part = reqwest::multipart::Part::bytes(file_data)
        .file_name(file_name.clone())
        .mime_str(&validation.magic_info.as_ref()
            .map(|m| m.mime_type.as_str())
            .unwrap_or("application/octet-stream"))
        .context("MIME-Type setzen")?;

    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("title", file_name);

    let mut client_builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300)); // 5 Min für große Dateien

    // macOS: native TLS
    #[cfg(target_os = "macos")]
    {
        client_builder = client_builder.use_rustls_tls();
    }

    let client = client_builder.build().context("HTTP-Client erstellen")?;

    let mut req = client
        .post(format!("{master_url}/api/v1/documents/upload"))
        .header("X-Api-Key", api_key)
        .multipart(form);

    if let Some(token) = session_token {
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
    }

    let resp = req.send().await.context("Upload-Anfrage an Master-Server fehlgeschlagen")?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.context("Server-Antwort parsen")?;

    if !status.is_success() {
        let err_msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Unbekannter Fehler");
        bail!("Server-Fehler ({}): {err_msg}", status.as_u16());
    }

    Ok(body)
}

/// Führt den vollständigen Upload-Prozess durch (Phase 2):
/// 1. Lokale Validierung (Magic Bytes, Größe, Typ)
/// 2. Upload via HTTP an den Stone-Master-Server
/// 3. Server übernimmt Chunking + Erasure-Coding + P2P-Shard-Verteilung
pub async fn process_upload(
    file_path: &str,
    master_url: &str,
    api_key: &str,
    session_token: Option<&str>,
) -> Result<UploadResult> {
    // Schritt 1: Validierung
    let validation = validate_file(file_path).map_err(|e| {
        anyhow!("Validierung fehlgeschlagen: {e}")
    })?;

    if !validation.valid {
        return Ok(UploadResult {
            success: false,
            file_hash: String::new(),
            file_name: validation.file_name,
            file_size: validation.file_size,
            magic_info: validation.magic_info,
            error: Some("Validierung fehlgeschlagen".into()),
            doc_id: None,
            block_index: None,
            block_hash: None,
            version: None,
            chunk_count: None,
            encrypted: None,
            signed: None,
            shards_distributed: None,
        });
    }

    // Schritt 2: An Master-Server senden
    let server_response = send_to_master_server(
        file_path,
        &validation,
        master_url,
        api_key,
        session_token,
    )
    .await
    .map_err(|e| anyhow!("Upload fehlgeschlagen: {e}"))?;

    Ok(UploadResult {
        success: true,
        file_hash: validation.sha256_hash.clone(),
        file_name: validation.file_name,
        file_size: validation.file_size,
        magic_info: validation.magic_info,
        error: None,
        doc_id: server_response.get("doc_id").and_then(|v| v.as_str()).map(String::from),
        block_index: server_response.get("block_index").and_then(|v| v.as_u64()),
        block_hash: server_response.get("block_hash").and_then(|v| v.as_str()).map(String::from),
        version: server_response.get("version").and_then(|v| v.as_u64()).map(|v| v as u32),
        chunk_count: None, // Server gibt das aktuell nicht zurück
        encrypted: server_response.get("encrypted").and_then(|v| v.as_bool()),
        signed: server_response.get("signed").and_then(|v| v.as_bool()),
        shards_distributed: Some(true), // Wenn Server 201 OK → Shards verteilt
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_detect_pe_executable() {
        let mut data = vec![0u8; 0x84];
        data[0] = b'M';
        data[1] = b'Z';
        let pe_offset: u32 = 0x80;
        data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;

        let info = detect_file_type(&data);
        assert!(info.is_some());
        assert!(info.unwrap().is_executable);
    }

    #[test]
    fn test_detect_elf_executable() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        let info = detect_file_type(&data);
        assert!(info.is_some());
        assert!(info.unwrap().is_executable);
    }

    #[test]
    fn test_detect_zip() {
        let data = b"PK\x03\x04\x00\x00\x00\x00".to_vec();
        let info = detect_file_type(&data);
        assert!(info.is_some());
        let info = info.unwrap();
        assert!(!info.is_executable);
        assert!(info.is_archive);
    }

    #[test]
    fn test_detect_png() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
        let info = detect_file_type(&data);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.mime_type, "image/png");
        assert!(!info.is_executable);
    }

    #[test]
    fn test_detect_text() {
        let data = b"Hello World! This is a text file.\nWith multiple lines.\n".to_vec();
        let info = detect_file_type(&data);
        assert!(info.is_some());
        let info = info.unwrap();
        assert!(!info.is_executable);
        assert_eq!(info.mime_type, "text/plain");
    }

    #[test]
    fn test_validate_blocked_exe() {
        let tmp = std::env::temp_dir().join("test_blocked.exe");
        let mut f = fs::File::create(&tmp).unwrap();
        f.write_all(b"MZ\x90\x00").unwrap();
        f.flush().unwrap();

        let result = validate_file(tmp.to_str().unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string().to_lowercase();
        assert!(
            err.contains("ausführbar") || err.contains("endung"),
            "Fehler sollte blockierte Datei melden, war: {err}"
        );

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_validate_zip_allowed() {
        let tmp = std::env::temp_dir().join("test_allowed.zip");
        let mut f = fs::File::create(&tmp).unwrap();
        f.write_all(b"PK\x03\x04Hello World").unwrap();
        f.flush().unwrap();

        let result = validate_file(tmp.to_str().unwrap());
        assert!(result.is_ok(), "ZIP sollte erlaubt sein: {:?}", result.err());
        let v = result.unwrap();
        assert!(v.valid);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_size_limit() {
        let tmp = std::env::temp_dir().join("test_too_large.bin");
        let f = fs::File::create(&tmp).unwrap();
        f.set_len(MAX_FILE_SIZE + 1).unwrap();

        let result = validate_file(tmp.to_str().unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("zu groß"), "Fehler: {err}");

        let _ = fs::remove_file(&tmp);
    }
}