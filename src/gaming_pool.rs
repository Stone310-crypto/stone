//! Encrypted gaming-pool storage.
//!
//! Erlaubt es einem Game-Owner, die Mnemonic seiner Gaming-Pool-Wallet einmalig
//! per signed Owner-Challenge auf dem Node zu hinterlegen. Die Mnemonic wird
//! mit AES-256-GCM verschlüsselt gespeichert (`stone_data/gaming_pools/<game_id>.enc`).
//!
//! Beim Play-Drop greift der Server auf diesen Eintrag zurück — der Plugin
//! braucht dadurch nur seinen Game-API-Key und keine Env-Vars mehr.
//!
//! Datei-Layout (binär):
//!   16 Byte Magic ("STONEPOOLENC\0\0\0\0")
//!   16 Byte Salt (Argon2id)
//!   12 Byte Nonce (AES-GCM)
//!    N Byte Ciphertext (Mnemonic-Plaintext + GCM-Tag)
//!
//! Der Passphrase-Resolution-Pfad mirroring validator_key:
//!   1. Env `STONE_DATA_PASSPHRASE`
//!   2. `stone_data/data_passphrase.key` (Auto-Datei, chmod 600)
//!   3. Neu generieren + speichern
//!
//! Die Datei lebt **lokal** auf dem Master-Node und wird nicht repliziert.

use std::fs;
use std::path::PathBuf;

use crate::blockchain::data_dir;

const MAGIC: &[u8; 16] = b"STONEPOOLENC\0\0\0\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

fn pools_dir() -> PathBuf {
    let mut p = PathBuf::from(data_dir());
    p.push("gaming_pools");
    p
}

fn pool_file(game_id: &str) -> PathBuf {
    let safe: String = game_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let mut p = pools_dir();
    p.push(format!("{safe}.enc"));
    p
}

fn passphrase_file() -> PathBuf {
    let mut p = PathBuf::from(data_dir());
    p.push("data_passphrase.key");
    p
}

/// Auflösung: Env > Auto-Datei > Neu generieren (chmod 600).
pub fn resolve_data_passphrase() -> String {
    if let Ok(v) = std::env::var("STONE_DATA_PASSPHRASE") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    let path = passphrase_file();
    if let Ok(s) = fs::read_to_string(&path) {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // Neu generieren
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let pass = hex::encode(buf);
    let _ = fs::create_dir_all(data_dir());
    if fs::write(&path, &pass).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
    }
    pass
}

fn derive_key(pass: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .expect("Argon2id KDF");
    key
}

fn encrypt(plaintext: &[u8], pass: &str) -> Vec<u8> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm};
    use rand::RngCore;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(pass, &salt);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("AES-GCM encrypt");

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

fn decrypt(data: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm};

    if data.len() < MAGIC.len() + SALT_LEN + NONCE_LEN + 16 {
        return Err("Datei zu klein".into());
    }
    if &data[..MAGIC.len()] != MAGIC {
        return Err("Ungültiges Magic-Byte".into());
    }
    let off = MAGIC.len();
    let salt: [u8; SALT_LEN] = data[off..off + SALT_LEN].try_into().unwrap();
    let off = off + SALT_LEN;
    let nonce: [u8; NONCE_LEN] = data[off..off + NONCE_LEN].try_into().unwrap();
    let off = off + NONCE_LEN;
    let ct = &data[off..];

    let key = derive_key(pass, &salt);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let n = GenericArray::from_slice(&nonce);
    cipher
        .decrypt(n, ct)
        .map_err(|_| "Entschlüsselung fehlgeschlagen — Passphrase falsch?".to_string())
}

/// Speichert die Pool-Mnemonic verschlüsselt für ein Spiel.
pub fn save_pool(game_id: &str, mnemonic: &str, pass: &str) -> Result<(), String> {
    fs::create_dir_all(pools_dir()).map_err(|e| format!("mkdir: {e}"))?;
    let blob = encrypt(mnemonic.trim().as_bytes(), pass);
    let path = pool_file(game_id);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &blob).map_err(|e| format!("write: {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_pool_mnemonic(game_id: &str, pass: &str) -> Result<String, String> {
    let path = pool_file(game_id);
    let data = fs::read(&path).map_err(|_| "Pool nicht konfiguriert".to_string())?;
    let plain = decrypt(&data, pass)?;
    String::from_utf8(plain).map_err(|_| "Pool-Plaintext kein UTF-8".to_string())
}

pub fn is_configured(game_id: &str) -> bool {
    pool_file(game_id).exists()
}

pub fn delete_pool(game_id: &str) -> Result<(), String> {
    let path = pool_file(game_id);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| format!("rm: {e}"))?;
    }
    Ok(())
}
