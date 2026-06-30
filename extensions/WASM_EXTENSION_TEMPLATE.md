# 🧩 Stone WASM Extension Template

So erstellst du eine neue Extension für den Stone Dashboard Extension-Store.

## Projektstruktur

```
my-extension/
├── Cargo.toml          # Rust-Projekt mit wasm32 Target
├── src/
│   └── lib.rs          # Extension-Logik
├── build.sh            # Build-Script (WASM kompilieren)
├── README.md           # Beschreibung für GitHub
└── .github/
    └── workflows/
        └── release.yml # GitHub Actions: Auto-Release bei Tag
```

---

## 1. `Cargo.toml`

```toml
[package]
name = "my-extension"
version = "1.0.0"
edition = "2021"
description = "Meine Extension für Stone Dashboard"

[lib]
crate-type = ["cdylib"]

[dependencies]
# Minimale Abhängigkeiten für WASM
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Optional: Für HTTP-Requests aus der Extension
# reqwest = { version = "0.12", features = ["json"], default-features = false }

[profile.release]
opt-level = "s"     # Size-optimiert (wichtig für WASM!)
lto = true          # Link-Time Optimization
strip = true        # Debug-Symbole entfernen
codegen-units = 1   # Bessere Optimierung
```

---

## 2. `src/lib.rs`

```rust
use serde::{Deserialize, Serialize};

// ─── Extension API ─────────────────────────────────────────────────

/// Wird vom Dashboard nach dem Laden aufgerufen.
/// Hier initialisierst du deine Extension (UI-Registrierung, Event-Listener, etc.)
#[no_mangle]
pub extern "C" fn init() {
    // Extension-Logik hier
}

/// Wird vom Dashboard aufgerufen, wenn die Extension deinstalliert wird.
#[no_mangle]
pub extern "C" fn shutdown() {
    // Cleanup hier
}

/// Gibt den Namen der Extension zurück (für Debug/Logging).
#[no_mangle]
pub extern "C" fn name() -> *const u8 {
    b"My Extension\0".as_ptr()
}

/// Gibt die Version zurück.
#[no_mangle]
pub extern "C" fn version() -> *const u8 {
    b"1.0.0\0".as_ptr()
}

// ─── Beispiel: Gaming-Extension ────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct GameRegistration {
    game_id: String,
    name: String,
    genre: String,
}

/// Registriert ein Spiel (wird vom Dashboard per WASM aufgerufen).
#[no_mangle]
pub extern "C" fn register_game(json_ptr: *const u8, json_len: usize) -> *const u8 {
    let json = unsafe {
        std::slice::from_raw_parts(json_ptr, json_len)
    };
    let json_str = std::str::from_utf8(json).unwrap_or("{}");
    
    // Game-Registrierung verarbeiten...
    let _game: GameRegistration = serde_json::from_str(json_str).unwrap_or(GameRegistration {
        game_id: String::new(),
        name: "Unknown".into(),
        genre: "unknown".into(),
    });
    
    // Ergebnis zurückgeben
    let result = b"{\"ok\": true}\0";
    result.as_ptr()
}
```

---

## 3. `build.sh`

```bash
#!/bin/bash
# Baut die Extension als WASM-Modul
set -e

echo "🦀 Compiling WASM extension..."

# WASM-Target installieren (einmalig)
rustup target add wasm32-unknown-unknown

# Release-Build
cargo build --release --target wasm32-unknown-unknown

# Optional: Mit wasm-opt noch kleiner machen
if command -v wasm-opt &>/dev/null; then
    wasm-opt -Oz target/wasm32-unknown-unknown/release/my_extension.wasm \
        -o target/wasm32-unknown-unknown/release/module.wasm
else
    cp target/wasm32-unknown-unknown/release/my_extension.wasm \
       target/wasm32-unknown-unknown/release/module.wasm
fi

echo "✅ module.wasm erstellt:"
ls -lh target/wasm32-unknown-unknown/release/module.wasm
```

---

## 4. GitHub Release Workflow (`.github/workflows/release.yml`)

```yaml
name: Release Extension

on:
  push:
    tags:
      - 'v*'  # z.B. v1.0.0

jobs:
  build-and-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown

      - name: Install wasm-opt
        run: |
          npm install -g wasm-opt
          # oder: cargo install wasm-opt

      - name: Build WASM
        run: |
          cargo build --release --target wasm32-unknown-unknown
          cp target/wasm32-unknown-unknown/release/*.wasm module.wasm

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: module.wasm
          generate_release_notes: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## 5. Release-Prozess

```bash
# 1. Version in Cargo.toml anpassen

# 2. Änderungen committen
git add .
git commit -m "v1.0.0: Meine Extension"

# 3. Tag setzen + pushen
git tag v1.0.0
git push origin main --tags

# 4. GitHub Actions baut automatisch und erstellt ein Release
#    mit module.wasm als Asset

# 5. index.json im Store-Repo aktualisieren:
#    - version auf "1.0.0" setzen
#    - ggf. description/changelog anpassen
```

---

## 6. Extension-Store aktualisieren

Nach jedem Release einer Extension im `stonechain/extensions` Repo die `index.json` updaten:

```bash
# Im stonechain/extensions Repo:
git clone https://github.com/Stone310-crypto/extensions.git
cd extensions

# index.json bearbeiten → version hochsetzen
nano index.json

git add index.json
git commit -m "Update gaming-extension to v1.0.1"
git push
```

Das Dashboard lädt dann automatisch die neue Version beim nächsten `get_available_extensions()` Aufruf.
