//! stone-keygen – Generiert ein Ed25519-Keypair für das Stone Update-System.
//!
//! Usage:
//!   stone-keygen [output-dir]
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

fn main() {
    let output_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".".to_string());

    let output_path = Path::new(&output_dir);
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
