# 🏗️ Stone Extension Store — GitHub Setup

So richtest du den Extension-Store auf GitHub ein.

## Schritt 1: Store-Repository erstellen

```bash
# 1. Auf GitHub: Neues Repository "extensions" erstellen
#    https://github.com/new
#    → Owner: Stone310-crypto
#    → Name: extensions
#    → Public
#    → Kein README (wir pushen unser eigenes)

# 2. Lokal clonen und index.json reinlegen
git clone https://github.com/Stone310-crypto/extensions.git
cd extensions
cp /Users/leon/stone/extensions/index.json .
git add index.json
git commit -m "Initial extension store index"
git push
```

## Schritt 2: Extension-Repositories erstellen

⚠️ **Wichtig**: Jede Extension ist ein EIGENSTÄNDIGES Git-Repository — nicht im Stone-Monorepo!

```bash
# Gaming-Extension
cd /tmp
cp -r /Users/leon/stone/extensions/gaming-extension /tmp/gaming-extension
cd /tmp/gaming-extension
rm -rf .git 2>/dev/null   # Altes Git entfernen falls vorhanden
git init
git add .
git commit -m "Initial gaming extension v1.0.0"
gh repo create Stone310-crypto/gaming-extension --public --source=. --push

# Dashboard-Extension (von Template kopieren)
cd /tmp
cp -r /Users/leon/stone/extensions/gaming-extension /tmp/dashboard-extension
cd /tmp/dashboard-extension
rm -rf .git 2>/dev/null
# → Cargo.toml: name = "dashboard-extension"
# → src/lib.rs: Code anpassen
git init && git add . && git commit -m "Initial dashboard extension"
gh repo create Stone310-crypto/dashboard-extension --public --source=. --push

# 2FA-Extension
cd /tmp
cp -r /Users/leon/stone/extensions/gaming-extension /tmp/2fa-extension
cd /tmp/2fa-extension
rm -rf .git 2>/dev/null
# → Cargo.toml: name = "2fa-extension"
# → src/lib.rs: Code anpassen
git init && git add . && git commit -m "Initial 2FA extension"
gh repo create Stone310-crypto/2fa-extension --public --source=. --push
```

## Schritt 3: Erstes Release erstellen

```bash
# In jedem Extension-Repo:
cd gaming-extension

# Version taggen
git tag v1.0.0
git push origin main --tags

# WASM bauen
bash build.sh

# Release mit module.wasm erstellen
gh release create v1.0.0 module.wasm \
    --title "Gaming Extension v1.0.0" \
    --notes "Erste Version: Spiele-Registrierung, Item-Trading, Marktplatz"
```

## Schritt 4: GitHub Actions (optional, für Auto-Release)

In jedem Extension-Repo `.github/workflows/release.yml` anlegen:

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - run: cargo build --release --target wasm32-unknown-unknown
      - run: cp target/wasm32-unknown-unknown/release/*.wasm module.wasm
      - uses: softprops/action-gh-release@v1
        with:
          files: module.wasm
```

Dann passiert bei `git tag v1.0.1 && git push --tags` alles automatisch.

## Schritt 5: index.json aktuell halten

Nach jedem Release die `index.json` im Store-Repo updaten:

```bash
cd extensions  # Store-Repo

# Version in index.json hochsetzen
# → "version": "1.0.0" → "1.0.1"

git add index.json
git commit -m "Update gaming-extension to v1.0.1"
git push
```

## Verzeichnisstruktur nach Setup

```
GitHub:
  Stone310-crypto/
    extensions/              ← Store (index.json)
    gaming-extension/        ← 🎮 WASM-Modul
    dashboard-extension/     ← 📊 WASM-Modul
    2fa-extension/           ← 🔐 WASM-Modul

Lokal:
  stone/
    extensions/
      index.json                  ← Store-Index
      WASM_EXTENSION_TEMPLATE.md  ← Doku
      gaming-extension/
        Cargo.toml
        src/lib.rs
        build.sh
```

## Dashboard-Konfiguration

In der Dashboard `.env` oder via Env-Var:

```bash
# Standard (falls kein Store):
# → Fallback mit 3 Demo-Extensions

# Mit eigenem Store:
STONE_EXTENSION_STORE_URL="https://raw.githubusercontent.com/Stone310-crypto/extensions/main"
```

Die `index.json` wird dann von dort geladen statt vom Fallback.
