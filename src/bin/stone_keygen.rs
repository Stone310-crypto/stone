//! stone-keygen – Generiert Schlüssel für das Stone-Netzwerk.
//!
//! Usage:
//!   stone-keygen [output-dir]          – Ed25519 Update-Signing-Keypair
//!   stone-keygen --admin-key           – Admin-API-Key generieren (stdout + stone_data/admin_key.bin)
//!   stone-keygen --admin-key --stdout  – Admin-API-Key nur auf stdout ausgeben
//!   stone-keygen --show-key            – Aktuellen API/Admin-Key anzeigen
//!
//! Erzeugt:
//!   <output-dir>/update_signing.key   – Private Key (hex, 32 Bytes)
//!   <output-dir>/update_signing.pub   – Public Key (hex, 32 Bytes)
//!
//! Der Public Key muss auf allen Nodes in `stone_data/trusted_update_keys.txt`
//! eingetragen werden (eine Zeile pro Key).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{fs, path::Path};

fn generate_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("sk_{}", hex::encode(bytes))
}

fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| "stone_data".to_string())
}

fn cmd_admin_key(stdout_only: bool) {
    let key = generate_api_key();

    if stdout_only {
        println!("{key}");
        return;
    }

    let dir = data_dir();
    let _ = fs::create_dir_all(&dir);
    let key_path = format!("{dir}/admin_key.bin");

    if let Err(e) = fs::write(&key_path, &key) {
        eprintln!("Fehler beim Speichern: {e}");
        std::process::exit(1);
    }

    // Permissions setzen (nur Owner lesen)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&key_path, perms);
    }

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Admin-API-Key generiert                                        ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                 ║");
    println!("║  Key:  {key}");
    println!("║  Datei: {key_path:<54}║");
    println!("║                                                                 ║");
    println!("║  Verwendung:                                                    ║");
    println!("║  • Mac App → Einstellungen → Admin API-Key einfügen             ║");
    println!("║  • curl -H 'x-api-key: {key}'");
    println!("║  • Oder ENV: STONE_ADMIN_KEY={key}");
    println!("║                                                                 ║");
    println!("║  Auf Remote-Nodes diese Datei kopieren:                         ║");
    println!("║    scp {key_path} user@node:stone_data/admin_key.bin");
    println!("║                                                                 ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}

fn cmd_show_key() {
    let dir = data_dir();

    // 1. STONE_ADMIN_KEY env
    if let Ok(v) = std::env::var("STONE_ADMIN_KEY") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            println!("Admin-Key (ENV STONE_ADMIN_KEY): {v}");
            return;
        }
    }

    // 2. admin_key.bin
    let admin_path = format!("{dir}/admin_key.bin");
    if let Ok(data) = fs::read_to_string(&admin_path) {
        let t = data.trim();
        if !t.is_empty() {
            println!("Admin-Key ({admin_path}): {t}");
            return;
        }
    }

    // 3. token.bin (fallback = api_key)
    let token_path = format!("{dir}/token.bin");
    if let Ok(data) = fs::read_to_string(&token_path) {
        let t = data.trim();
        if !t.is_empty() {
            println!("API-Key als Admin-Fallback ({token_path}): {t}");
            println!("⚠️  Kein separater Admin-Key gesetzt. Generiere einen mit: stone-keygen --admin-key");
            return;
        }
    }

    eprintln!("Kein API-Key oder Admin-Key gefunden in {dir}/");
    std::process::exit(1);
}

fn cmd_update_signing(output_dir: &str) {
    let output_path = Path::new(output_dir);
    fs::create_dir_all(output_path).expect("Verzeichnis erstellen");

    // Keypair generieren
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.as_bytes());

    // Private Key speichern
    let key_path = output_path.join("update_signing.key");
    fs::write(&key_path, &secret_hex).expect("Private Key speichern");
    println!("🔑 Private Key: {}", key_path.display());

    // Public Key speichern
    let pub_path = output_path.join("update_signing.pub");
    fs::write(&pub_path, &public_hex).expect("Public Key speichern");
    println!("📢 Public Key:  {}", pub_path.display());

    println!();
    println!("Public Key (hex): {public_hex}");
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Nächste Schritte:                                              ║");
    println!("║                                                                 ║");
    println!("║  1. Private Key sicher aufbewahren (NIEMALS teilen!)            ║");
    println!("║  2. Public Key auf alle Nodes verteilen:                        ║");
    println!("║     echo '{public_hex}'");
    println!("║       >> stone_data/trusted_update_keys.txt                     ║");
    println!("║                                                                 ║");
    println!("║  Oder per ENV:                                                  ║");
    println!("║     STONE_UPDATE_TRUSTED_KEY={public_hex}");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    // Permissions auf Private Key setzen (nur Owner lesen)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&key_path, perms);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--admin-key") {
        let stdout_only = args.iter().any(|a| a == "--stdout");
        cmd_admin_key(stdout_only);
        return;
    }

    if args.iter().any(|a| a == "--show-key") {
        cmd_show_key();
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("stone-keygen – Schlüssel-Generator für das Stone-Netzwerk");
        println!();
        println!("Usage:");
        println!("  stone-keygen [output-dir]          Ed25519 Update-Signing-Keypair generieren");
        println!("  stone-keygen --admin-key           Admin-API-Key generieren → stone_data/admin_key.bin");
        println!("  stone-keygen --admin-key --stdout   Admin-API-Key nur auf stdout");
        println!("  stone-keygen --show-key            Aktuellen API/Admin-Key anzeigen");
        return;
    }

    let output_dir = args.get(1).map(|s| s.as_str()).unwrap_or(".");
    cmd_update_signing(output_dir);
}
