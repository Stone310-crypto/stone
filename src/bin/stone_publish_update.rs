//! stone-publish-update – Signiert und veröffentlicht ein Stone-Update.
//!
//! Usage:
//!   stone-publish-update \
//!     --binary <path-to-binary> \
//!     --key <path-to-signing-key> \
//!     --target <target-triple> \
//!     --node <http://node-url:port> \
//!     --api-key <admin-api-key> \
//!     [--changelog "Release notes"] \
//!     [--version <version>]   # Überschreibt die Version aus dem Binary
//!
//! Das Tool:
//! 1. Liest das Binary ein
//! 2. Berechnet SHA-256 Hash & chunked in 1 MiB Stücke
//! 3. Erstellt ein UpdateManifest
//! 4. Signiert mit Ed25519
//! 5. Sendet Manifest + alle Chunks per HTTP POST an den Node

use chrono::Utc;
use base64::Engine as _;
use stone::updater::{
    UpdateManifest, UPDATE_CHUNK_SIZE, chunk_binary, sha256_hex,
    sign_manifest, load_signing_key,
};
use std::{fs, path::Path, process};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut binary_path = None;
    let mut key_path = None;
    let mut target = None;
    let mut node_url = None;
    let mut api_key = None;
    let mut changelog = String::new();
    let mut version_override = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--binary" | "-b" => {
                i += 1;
                binary_path = Some(args[i].clone());
            }
            "--key" | "-k" => {
                i += 1;
                key_path = Some(args[i].clone());
            }
            "--target" | "-t" => {
                i += 1;
                target = Some(args[i].clone());
            }
            "--node" | "-n" => {
                i += 1;
                node_url = Some(args[i].clone());
            }
            "--api-key" | "-a" => {
                i += 1;
                api_key = Some(args[i].clone());
            }
            "--changelog" | "-c" => {
                i += 1;
                changelog = args[i].clone();
            }
            "--version" | "-v" => {
                i += 1;
                version_override = Some(args[i].clone());
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => {
                eprintln!("Unbekanntes Argument: {other}");
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    let binary_path = binary_path.unwrap_or_else(|| {
        eprintln!("Fehler: --binary ist erforderlich");
        print_usage();
        process::exit(1);
    });

    let key_path = key_path.unwrap_or_else(|| {
        eprintln!("Fehler: --key ist erforderlich");
        print_usage();
        process::exit(1);
    });

    let target = target.unwrap_or_else(|| {
        eprintln!("Fehler: --target ist erforderlich");
        print_usage();
        process::exit(1);
    });

    let node_url = node_url.unwrap_or_else(|| {
        eprintln!("Fehler: --node ist erforderlich");
        print_usage();
        process::exit(1);
    });

    let api_key = api_key.unwrap_or_else(|| {
        eprintln!("Fehler: --api-key ist erforderlich");
        print_usage();
        process::exit(1);
    });

    // ── Binary einlesen ──────────────────────────────────────────────────────

    println!("📦 Lese Binary: {binary_path}");
    let binary_data = fs::read(&binary_path).unwrap_or_else(|e| {
        eprintln!("Binary lesen: {e}");
        process::exit(1);
    });

    let binary_name = Path::new(&binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "stone-setup".to_string());

    let binary_hash = sha256_hex(&binary_data);
    let binary_size = binary_data.len() as u64;

    println!("   Größe: {} Bytes ({:.1} MiB)", binary_size, binary_size as f64 / 1048576.0);
    println!("   SHA-256: {binary_hash}");

    // ── Chunks erstellen ─────────────────────────────────────────────────────

    let chunks = chunk_binary(&binary_data);
    let chunk_hashes: Vec<String> = chunks.iter().map(|(_, h)| h.clone()).collect();

    println!("   Chunks: {} × {} Bytes", chunks.len(), UPDATE_CHUNK_SIZE);

    // ── Signing Key laden ────────────────────────────────────────────────────

    println!("🔑 Lade Signing Key: {key_path}");
    let signing_key = load_signing_key(Path::new(&key_path)).unwrap_or_else(|e| {
        eprintln!("Signing Key: {e}");
        process::exit(1);
    });
    let public_hex = hex::encode(signing_key.verifying_key().as_bytes());
    println!("   Public Key: {public_hex}");

    // ── Version bestimmen ────────────────────────────────────────────────────

    let version = version_override.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("📋 Version: {version}");

    // ── Manifest erstellen & signieren ───────────────────────────────────────

    let mut manifest = UpdateManifest {
        version: version.clone(),
        binary_hash,
        binary_size,
        target: target.clone(),
        binary_name: binary_name.clone(),
        chunk_hashes,
        chunk_size: UPDATE_CHUNK_SIZE,
        published_at: Utc::now(),
        changelog: changelog.clone(),
        signature: String::new(),
        signer_key: public_hex.clone(),
    };

    manifest.signature = sign_manifest(&manifest, &signing_key);
    println!("✅ Manifest signiert");

    // ── An Node senden ───────────────────────────────────────────────────────

    println!("🚀 Sende an Node: {node_url}");

    // Payload bauen: { manifest, chunks: [[index, base64_data], ...] }
    let chunk_array: Vec<serde_json::Value> = chunks
        .iter()
        .enumerate()
        .map(|(idx, (data, _hash))| {
            serde_json::json!({
                "index": idx,
                "data": base64::engine::general_purpose::STANDARD.encode(data),
            })
        })
        .collect();

    let payload = serde_json::json!({
        "manifest": manifest,
        "chunks": chunk_array,
    });

    // Synchroner HTTP-Client (kein Tokio-Runtime nötig)
    let url = format!("{}/api/v1/updates/publish", node_url.trim_end_matches('/'));

    println!("   POST {url}");
    println!("   Payload: {:.1} MiB", payload.to_string().len() as f64 / 1048576.0);

    // Wir nutzen einen einfachen Ansatz: Manifest als JSON-Datei speichern
    // und den User anweisen, es mit curl zu senden (da reqwest async ist).
    // Alternativ: Tokio-Runtime inline starten.

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio Runtime");

    let result = rt.block_on(async {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| format!("HTTP Client: {e}"))?;

        let resp = client
            .post(&url)
            .header("x-api-key", &api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("HTTP Request: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("HTTP {status}: {body}"))
        }
    });

    match result {
        Ok(body) => {
            println!("✅ Update erfolgreich veröffentlicht!");
            println!("   Response: {body}");
            println!();
            println!("╔══════════════════════════════════════════════════════════════════╗");
            println!("║  Update v{version} wurde an {node_url} gesendet.");
            println!("║  Der Node verteilt das Manifest automatisch per Gossipsub.      ║");
            println!("║                                                                 ║");
            println!("║  Andere Nodes laden das Update automatisch herunter.            ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
        }
        Err(e) => {
            eprintln!("❌ Fehler: {e}");

            // Manifest lokal speichern als Fallback
            let manifest_path = format!("update_manifest_v{version}.json");
            let json = serde_json::to_string_pretty(&manifest).unwrap();
            let _ = fs::write(&manifest_path, &json);
            eprintln!("   Manifest als Fallback gespeichert: {manifest_path}");
            eprintln!();
            eprintln!("   Manuell senden mit:");
            eprintln!("   curl -X POST {url} \\");
            eprintln!("     -H 'x-api-key: <key>' \\");
            eprintln!("     -H 'Content-Type: application/json' \\");
            eprintln!("     -d @publish_payload.json");

            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!(
        r#"
stone-publish-update – Stone P2P Update Publisher

USAGE:
    stone-publish-update [OPTIONS]

REQUIRED:
    --binary, -b <PATH>     Pfad zum kompilierten Binary
    --key, -k <PATH>        Pfad zum Ed25519 Signing Key (.key Datei)
    --target, -t <TRIPLE>   Ziel-Plattform (z.B. x86_64-unknown-linux-gnu)
    --node, -n <URL>        URL des Seed-Nodes (z.B. http://100.90.28.68:3000)
    --api-key, -a <KEY>     Admin API-Key des Nodes

OPTIONAL:
    --changelog, -c <TEXT>  Release Notes
    --version, -v <VER>     Version überschreiben (Standard: aus Cargo.toml)
    --help, -h              Diese Hilfe anzeigen

BEISPIEL:
    stone-publish-update \
        --binary target/x86_64-unknown-linux-gnu/release/stone-setup \
        --key keys/update_signing.key \
        --target x86_64-unknown-linux-gnu \
        --node http://100.90.28.68:3000 \
        --api-key sk_abc123 \
        --changelog "Bug fixes and performance improvements"
"#
    );
}
