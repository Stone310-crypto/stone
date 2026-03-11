#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  publish-update.sh – Stone P2P Update veröffentlichen                       ║
# ║                                                                              ║
# ║  Workflow:                                                                   ║
# ║  1. Cross-Compile für Linux x86_64 (cargo zigbuild)                         ║
# ║  2. Signiere mit Ed25519 Signing Key                                        ║
# ║  3. Sende an Seed-Node per HTTP                                             ║
# ║  4. Seed-Node broadcastet per Gossipsub an alle Peers                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ─── Ins Projekt-Root wechseln (egal von wo aufgerufen) ──────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# ─── Konfiguration ────────────────────────────────────────────────────────────

SIGNING_KEY="${STONE_SIGNING_KEY:-keys/update_signing.key}"
TARGET="${STONE_UPDATE_TARGET:-x86_64-unknown-linux-gnu}"
SEED_NODE="${STONE_SEED_NODE:-http://localhost:8080}"
API_KEY="${STONE_PUBLISH_API_KEY:-${STONE_API_KEY:-}}"
BINARY_NAME="stone-setup"
CHANGELOG="${1:-}"  # Erstes Argument = Changelog

# ─── Farben ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}ℹ  $*${NC}"; }
ok()    { echo -e "${GREEN}✅ $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠  $*${NC}"; }
error() { echo -e "${RED}❌ $*${NC}" >&2; }

# ─── Voraussetzungen prüfen ──────────────────────────────────────────────────

if [ -z "$API_KEY" ]; then
    # Versuche aus .env zu laden (STONE_PUBLISH_API_KEY hat Vorrang)
    if [ -f .env ]; then
        for KEY_VAR in STONE_PUBLISH_API_KEY STONE_API_KEY STONE_CLUSTER_API_KEY; do
            CANDIDATE=$(grep -E "^${KEY_VAR}=" .env | head -1 | cut -d'=' -f2 | tr -d '"' | tr -d "'")
            if [ -n "$CANDIDATE" ]; then
                API_KEY="$CANDIDATE"
                break
            fi
        done
    fi
    if [ -z "$API_KEY" ]; then
        error "API-Key nicht gefunden!"
        echo ""
        echo "  Setze den API-Key des Ziel-Servers:"
        echo "    STONE_API_KEY=sk_xxx ./scripts/publish-update.sh"
        echo ""
        echo "  Oder lege STONE_API_KEY in .env ab."
        exit 1
    fi
fi

info "Ziel-Node: ${SEED_NODE} (API-Key: ${API_KEY:0:12}...)"

if [ ! -f "$SIGNING_KEY" ]; then
    warn "Signing Key nicht gefunden: $SIGNING_KEY"
    echo ""
    echo "Generiere einen neuen Key:"
    echo "  cargo run --release --bin stone-keygen -- keys"
    echo ""
    echo "Oder setze STONE_SIGNING_KEY auf den Pfad zum Key."
    exit 1
fi

# ─── Schritt 1: Cross-Compile ────────────────────────────────────────────────

info "Cross-Compile für ${TARGET}..."

if command -v cargo-zigbuild &>/dev/null; then
    cargo zigbuild --release --target "$TARGET" --bin "$BINARY_NAME" 2>&1 | tail -5
else
    warn "cargo-zigbuild nicht installiert. Versuche normales cargo build..."
    cargo build --release --target "$TARGET" --bin "$BINARY_NAME" 2>&1 | tail -5
fi

BINARY_PATH="target/${TARGET}/release/${BINARY_NAME}"
if [ ! -f "$BINARY_PATH" ]; then
    error "Binary nicht gefunden: $BINARY_PATH"
    exit 1
fi

BINARY_SIZE=$(stat -f%z "$BINARY_PATH" 2>/dev/null || stat -c%s "$BINARY_PATH")
info "Binary: $BINARY_PATH ($(echo "scale=1; $BINARY_SIZE / 1048576" | bc) MiB)"
ok "Cross-Compile abgeschlossen"

# ─── Schritt 2: Version ermitteln ────────────────────────────────────────────

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
info "Version: ${VERSION}"

# ─── Schritt 3: Update veröffentlichen ───────────────────────────────────────

info "Sende Update an ${SEED_NODE}..."

PUBLISH_ARGS=(
    --binary "$BINARY_PATH"
    --key "$SIGNING_KEY"
    --target "$TARGET"
    --node "$SEED_NODE"
    --api-key "$API_KEY"
    --version "$VERSION"
)

if [ -n "$CHANGELOG" ]; then
    PUBLISH_ARGS+=(--changelog "$CHANGELOG")
fi

cargo run --release --bin stone-publish-update -- "${PUBLISH_ARGS[@]}"

echo ""
ok "Update v${VERSION} veröffentlicht!"
echo ""

# ─── Schritt 4: Download auf Remote-Server auslösen ──────────────────────────

info "Löse Download auf ${SEED_NODE} aus..."

DL_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${SEED_NODE}/api/v1/updates/download" \
    -H "x-api-key: ${API_KEY}" \
    -H "Content-Type: application/json" 2>/dev/null || true)

DL_HTTP_CODE=$(echo "$DL_RESPONSE" | tail -1)
DL_BODY=$(echo "$DL_RESPONSE" | sed '$d')

if [ "$DL_HTTP_CODE" = "202" ] || [ "$DL_HTTP_CODE" = "200" ]; then
    ok "Download gestartet auf ${SEED_NODE}"
    echo "  $DL_BODY" | head -3
else
    warn "Download-Trigger fehlgeschlagen (HTTP ${DL_HTTP_CODE})"
    echo "  $DL_BODY" | head -3
    echo ""
    echo "  Manuell starten:"
    echo "    curl -X POST ${SEED_NODE}/api/v1/updates/download -H 'x-api-key: ${API_KEY}'"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  Update-Status prüfen:                                             ║"
echo "║  curl ${SEED_NODE}/api/v1/updates/status | jq                      ║"
echo "║                                                                    ║"
echo "║  Manuell installieren (auf jedem Node):                            ║"
echo "║  curl -X POST ${SEED_NODE}/api/v1/updates/install \\               ║"
echo "║    -H 'x-api-key: <key>'                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
