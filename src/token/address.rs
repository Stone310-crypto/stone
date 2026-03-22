//! Stone Adressformat – Bech32m mit Prefix "stone"
//!
//! Wallet-Adressen werden als Bech32m-kodierte Ed25519 Public Keys dargestellt:
//!
//! ```text
//! stone1d2ug5njht4ku8ngaf9s7qpwxp8ywzujx4tfy7esktqexxejndyeqcwh6hp
//! ```
//!
//! ## Format
//!
//! | Teil       | Beschreibung                                  |
//! |------------|-----------------------------------------------|
//! | `stone`    | Human-Readable Part (HRP) — identifiziert das Netzwerk |
//! | `1`        | Bech32-Separator                              |
//! | `d2ug5n…`  | 32 Byte Public Key, Base32-kodiert            |
//! | letzte 6   | Bech32m-Checksum (Fehlererkennung)            |
//!
//! ## Intern vs. Extern
//!
//! - **Intern** (Ledger, Blockchain, Signierung): Hex-Format (64 Zeichen)
//! - **Extern** (API, UI, User-facing): Bech32m-Format (`stone1...`)
//! - Pool-Adressen (`pool:staking`, `pool:onboarding` etc.) bleiben unverändert

use bech32::{Bech32m, Hrp};

/// Human-Readable Part für Stone-Adressen.
const HRP: Hrp = Hrp::parse_unchecked("stone");

/// Kodiert einen 32-Byte Ed25519 Public Key als Bech32m-Adresse.
///
/// Beispiel: `stone1d2ug5njht4ku8ngaf9s7qpwxp8ywzujx4tfy7esktqexxejndyeqcwh6hp`
pub fn encode(pubkey_bytes: &[u8; 32]) -> String {
    // Bech32m-Encoding kann bei gültigem HRP und 32 Bytes nicht fehlschlagen
    bech32::encode::<Bech32m>(HRP, pubkey_bytes)
        .expect("Bech32m-Encoding eines 32-Byte Keys darf nicht fehlschlagen")
}

/// Dekodiert eine `stone1...` Bech32m-Adresse zurück in 32 Byte Public Key.
///
/// Akzeptiert sowohl Lower- als auch Uppercase-Adressen.
/// Gibt `None` zurück wenn:
/// - Die Adresse kein gültiges Bech32m ist
/// - Das HRP nicht "stone" ist
/// - Die Nutzlast nicht exakt 32 Byte hat
pub fn decode(address: &str) -> Option<[u8; 32]> {
    let (hrp, data) = bech32::decode(address).ok()?;
    if hrp != HRP || data.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data);
    Some(bytes)
}

/// Kodiert einen Hex-String (64 Zeichen) in eine `stone1...`-Adresse.
///
/// Gibt `None` zurück wenn der Hex-String ungültig ist.
pub fn hex_to_bech32(hex_addr: &str) -> Option<String> {
    let bytes = hex::decode(hex_addr).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(encode(bytes.as_slice().try_into().unwrap()))
}

/// Konvertiert eine Adresse (Bech32m oder Hex) in den internen Hex-String.
///
/// Akzeptiert:
/// - `stone1...` → dekodiert Bech32m → Hex
/// - 64 Hex-Zeichen → direkt durchgereicht
/// - Pool-Adressen (`pool:...`) → direkt durchgereicht
/// - Spezial-Konten (`system`, `burn`, `memorial`, `forever`) → direkt durchgereicht
///
/// Gibt `None` zurück bei ungültigem Format.
pub fn normalize_to_hex(address: &str) -> Option<String> {
    // Pool-Adressen und Spezial-Konten direkt durchreichen
    if address.starts_with("pool:") || matches!(address, "system" | "burn" | "memorial" | "forever") {
        return Some(address.to_string());
    }

    // Bech32m-Adresse (stone1... oder STONE1...)
    if address.to_lowercase().starts_with("stone1") {
        return decode(address).map(hex::encode);
    }

    // Hex-Adresse (64 Zeichen, nur Hex)
    if address.len() == 64 && address.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(address.to_lowercase());
    }

    None
}

/// Konvertiert eine interne Adresse in das Display-Format.
///
/// - 64-Zeichen-Hex → `stone1...`
/// - Pool-/Spezial-Adressen → unverändert
pub fn to_display(internal_addr: &str) -> String {
    if internal_addr.len() == 64 && internal_addr.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex_to_bech32(internal_addr).unwrap_or_else(|| internal_addr.to_string())
    } else {
        internal_addr.to_string()
    }
}

/// Prüft ob ein String eine gültige Stone-Adresse ist (Bech32m, Hex oder Pool).
pub fn is_valid(address: &str) -> bool {
    normalize_to_hex(address).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let key: [u8; 32] = [
            0x6a, 0xb8, 0xa4, 0x9a, 0x17, 0x55, 0xb4, 0xc9,
            0xe8, 0xba, 0x90, 0xbc, 0x03, 0x8a, 0x30, 0x70,
            0x9c, 0x0f, 0x28, 0x79, 0xaa, 0xc4, 0xf2, 0xf3,
            0xde, 0x16, 0x09, 0x89, 0xd9, 0x29, 0xd3, 0x23,
        ];
        let addr = encode(&key);
        assert!(addr.starts_with("stone1"), "Adresse muss mit stone1 beginnen: {addr}");

        let decoded = decode(&addr).expect("Dekodierung muss klappen");
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_hex_to_bech32_and_back() {
        let hex_addr = "6ab8a49a1755b4c9e8ba90bc038a30709c0f2879aac4f2f3de160989d929d323";
        let bech32_addr = hex_to_bech32(hex_addr).unwrap();
        assert!(bech32_addr.starts_with("stone1"));

        let back = normalize_to_hex(&bech32_addr).unwrap();
        assert_eq!(back, hex_addr);
    }

    #[test]
    fn test_normalize_hex_passthrough() {
        let hex_addr = "6ab8a49a1755b4c9e8ba90bc038a30709c0f2879aac4f2f3de160989d929d323";
        assert_eq!(normalize_to_hex(hex_addr).unwrap(), hex_addr);
    }

    #[test]
    fn test_normalize_pool_passthrough() {
        assert_eq!(normalize_to_hex("pool:staking").unwrap(), "pool:staking");
        assert_eq!(normalize_to_hex("pool:onboarding").unwrap(), "pool:onboarding");
        assert_eq!(normalize_to_hex("system").unwrap(), "system");
        assert_eq!(normalize_to_hex("burn").unwrap(), "burn");
    }

    #[test]
    fn test_to_display_hex_to_bech32() {
        let hex_addr = "6ab8a49a1755b4c9e8ba90bc038a30709c0f2879aac4f2f3de160989d929d323";
        let display = to_display(hex_addr);
        assert!(display.starts_with("stone1"));
    }

    #[test]
    fn test_to_display_pool_unchanged() {
        assert_eq!(to_display("pool:staking"), "pool:staking");
        assert_eq!(to_display("system"), "system");
    }

    #[test]
    fn test_invalid_addresses() {
        assert!(normalize_to_hex("").is_none());
        assert!(normalize_to_hex("not_an_address").is_none());
        assert!(normalize_to_hex("stone1invalid").is_none());
        assert!(normalize_to_hex("abc123").is_none()); // too short hex
    }

    #[test]
    fn test_is_valid() {
        let hex_addr = "6ab8a49a1755b4c9e8ba90bc038a30709c0f2879aac4f2f3de160989d929d323";
        assert!(is_valid(hex_addr));
        assert!(is_valid(&hex_to_bech32(hex_addr).unwrap()));
        assert!(is_valid("pool:staking"));
        assert!(!is_valid("garbage"));
    }

    #[test]
    fn test_case_insensitive_decode() {
        let hex_addr = "6ab8a49a1755b4c9e8ba90bc038a30709c0f2879aac4f2f3de160989d929d323";
        let bech32_addr = hex_to_bech32(hex_addr).unwrap();
        let upper = bech32_addr.to_uppercase();
        // Bech32 decode must handle uppercase
        let decoded = normalize_to_hex(&upper);
        assert_eq!(decoded.unwrap(), hex_addr);
    }
}
