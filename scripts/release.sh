#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  release.sh – Stone Unified Release Pipeline                                ║
# ║                                                                              ║
# ║  Vereint alle Deployment-Schritte in einem Befehl:                          ║
# ║  1. Cross-Compile (x86_64 + aarch64)                                       ║
# ║  2. SSH-Deploy auf alle Nodes (parallel + atomic swap)                      ║
# ║  3. OTA-Update per P2P veröffentlichen                                      ║
# ║  4. Docker-Image bauen + pushen                                             ║
# ║                                                                              ║
# ║  Usage:                                                                      ║
# ║    ./scripts/release.sh                    # Alles (Build + Deploy + OTA)   ║
# ║    ./scripts/release.sh --steps build,ssh  # Nur Build + SSH-Deploy        ║
# ║    ./scripts/release.sh --steps ota        # Nur OTA-Publish               ║
# ║    ./scripts/release.sh --steps docker     # Nur Docker-Image              ║
# ║    ./scripts/release.sh --dry-run          # Zeigt was gemacht würde       ║
# ║    ./scripts/release.sh --changelog "..."  # Mit Release-Notes              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ─── Farben ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${BLUE}[release]${NC} $*"; }
ok()      { echo -e "${GREEN}[release]${NC} ✅ $*"; }
warn()    { echo -e "${YELLOW}[release]${NC} ⚠  $*"; }
error()   { echo -e "${RED}[release]${NC} ❌ $*" >&2; }
step()    { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }

# ─── Konfiguration ────────────────────────────────────────────────────────────

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

STEPS="build,ssh,ota"    # Standard: alles außer Docker
DRY_RUN=false
CHANGELOG=""
SSH_NODE=""               # Leer = alle Nodes
SKIP_CONFIRM=false

# ─── Argumente parsen ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --steps)
            STEPS="$2"; shift 2 ;;
        --changelog|-c)
            CHANGELOG="$2"; shift 2 ;;
        --node|-n)
            SSH_NODE="$2"; shift 2 ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --all)
            STEPS="build,ssh,ota,docker"; shift ;;
        --yes|-y)
            SKIP_CONFIRM=true; shift ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --steps <s1,s2,...>  Schritte: build, ssh, ota, docker (Standard: build,ssh,ota)"
            echo "  --all               Alle Schritte inkl. Docker"
            echo "  --changelog, -c     Release-Notes für OTA"
            echo "  --node, -n          Nur einen bestimmten SSH-Node deployen"
            echo "  --dry-run           Nur anzeigen was gemacht würde"
            echo "  --yes, -y           Keine Bestätigung abfragen"
            echo "  --help, -h          Diese Hilfe"
            exit 0 ;;
        *)
            error "Unbekannte Option: $1"
            exit 1 ;;
    esac
done

# ─── Steps parsen ─────────────────────────────────────────────────────────────

DO_BUILD=false
DO_SSH=false
DO_OTA=false
DO_DOCKER=false

IFS=',' read -ra STEP_ARRAY <<< "$STEPS"
for s in "${STEP_ARRAY[@]}"; do
    case "$s" in
        build)   DO_BUILD=true ;;
        ssh)     DO_SSH=true ;;
        ota)     DO_OTA=true ;;
        docker)  DO_DOCKER=true ;;
        *)       error "Unbekannter Step: $s"; exit 1 ;;
    esac
done

# ─── Banner ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}  ┌──────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │${NC}  🪨  ${GREEN}Stone Release Pipeline${NC}                   ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     v${VERSION} (${GIT_HASH})                      ${CYAN}│${NC}"
echo -e "${CYAN}  └──────────────────────────────────────────────┘${NC}"
echo ""

info "Steps: $STEPS"
[ -n "$CHANGELOG" ] && info "Changelog: $CHANGELOG"
[ "$DRY_RUN" = true ] && warn "DRY-RUN Modus — keine Änderungen"
echo ""

# ─── Bestätigung ──────────────────────────────────────────────────────────────

if [ "$SKIP_CONFIRM" = false ] && [ "$DRY_RUN" = false ]; then
    echo -e "  Release v${VERSION} mit Steps: ${YELLOW}${STEPS}${NC}"
    read -p "  Fortfahren? [Y/n] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]?$ ]]; then
        echo "Abgebrochen."
        exit 0
    fi
fi

FAILED=false

# ═════════════════════════════════════════════════════════════════════════════
# Step 1: Cross-Compile
# ═════════════════════════════════════════════════════════════════════════════

if [ "$DO_BUILD" = true ]; then
    step "Step 1: Cross-Compile (x86_64 + aarch64)"

    if [ "$DRY_RUN" = true ]; then
        info "Würde ausführen: ./build_linux.sh"
    else
        bash "$PROJECT_DIR/build_linux.sh"
        ok "Cross-Compile abgeschlossen"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 2: SSH-Deploy
# ═════════════════════════════════════════════════════════════════════════════

if [ "$DO_SSH" = true ]; then
    step "Step 2: SSH-Deploy (parallel upload + atomic swap)"

    if [ "$DRY_RUN" = true ]; then
        info "Würde ausführen: ./scripts/deploy.sh --skip-build ${SSH_NODE}"
    else
        DEPLOY_ARGS=(--skip-build)
        [ -n "$SSH_NODE" ] && DEPLOY_ARGS+=("$SSH_NODE")

        if bash "$SCRIPT_DIR/deploy.sh" "${DEPLOY_ARGS[@]}"; then
            ok "SSH-Deploy abgeschlossen"
        else
            error "SSH-Deploy fehlgeschlagen!"
            FAILED=true
        fi
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 3: OTA-Update veröffentlichen
# ═════════════════════════════════════════════════════════════════════════════

if [ "$DO_OTA" = true ]; then
    step "Step 3: OTA-Update veröffentlichen"

    # Für jede Architektur ein eigenes Manifest veröffentlichen
    TARGETS=("x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu")

    for TARGET in "${TARGETS[@]}"; do
        BINARY_PATH="target/${TARGET}/release/stone-setup"

        if [ ! -f "$BINARY_PATH" ]; then
            warn "Binary für ${TARGET} nicht gefunden — überspringe OTA"
            continue
        fi

        if [ "$DRY_RUN" = true ]; then
            info "Würde OTA publizieren: ${TARGET}"
        else
            info "OTA-Publish für ${TARGET}..."

            OTA_ARGS=(
                --binary "$BINARY_PATH"
                --target "$TARGET"
                --version "$VERSION"
            )

            # Signing Key
            SIGNING_KEY="${STONE_SIGNING_KEY:-keys/update_signing.key}"
            if [ ! -f "$SIGNING_KEY" ]; then
                warn "Signing Key nicht gefunden: $SIGNING_KEY — OTA übersprungen"
                continue
            fi
            OTA_ARGS+=(--key "$SIGNING_KEY")

            # Seed-Node
            SEED_NODE="${STONE_SEED_NODE:-}"
            if [ -z "$SEED_NODE" ]; then
                # Aus .env laden
                if [ -f .env ]; then
                    SEED_NODE=$(grep -E "^STONE_SEED_NODE=" .env | head -1 | cut -d'=' -f2 | tr -d '"' | tr -d "'" || true)
                fi
            fi
            if [ -z "$SEED_NODE" ]; then
                warn "STONE_SEED_NODE nicht gesetzt — OTA übersprungen"
                continue
            fi
            OTA_ARGS+=(--node "$SEED_NODE")

            # API-Key
            API_KEY="${STONE_PUBLISH_API_KEY:-${STONE_API_KEY:-}}"
            if [ -z "$API_KEY" ] && [ -f .env ]; then
                for KEY_VAR in STONE_PUBLISH_API_KEY STONE_API_KEY STONE_CLUSTER_API_KEY; do
                    CANDIDATE=$(grep -E "^${KEY_VAR}=" .env | head -1 | cut -d'=' -f2 | tr -d '"' | tr -d "'" || true)
                    if [ -n "$CANDIDATE" ]; then
                        API_KEY="$CANDIDATE"
                        break
                    fi
                done
            fi
            if [ -z "$API_KEY" ]; then
                warn "API-Key nicht gefunden — OTA übersprungen"
                continue
            fi
            OTA_ARGS+=(--api-key "$API_KEY")

            [ -n "$CHANGELOG" ] && OTA_ARGS+=(--changelog "$CHANGELOG")

            if cargo run --release --bin stone-publish-update -- "${OTA_ARGS[@]}"; then
                ok "OTA-Publish für ${TARGET} abgeschlossen"
            else
                error "OTA-Publish für ${TARGET} fehlgeschlagen!"
                FAILED=true
            fi
        fi
    done
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 4: Docker-Image bauen + pushen
# ═════════════════════════════════════════════════════════════════════════════

if [ "$DO_DOCKER" = true ]; then
    step "Step 4: Docker-Image (multi-arch)"

    if [ "$DRY_RUN" = true ]; then
        info "Würde ausführen: ./build_and_push.sh stone"
    else
        if bash "$PROJECT_DIR/build_and_push.sh" stone; then
            ok "Docker-Image gebaut und gepusht"
        else
            error "Docker-Build fehlgeschlagen!"
            FAILED=true
        fi
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Ergebnis
# ═════════════════════════════════════════════════════════════════════════════

echo ""
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  DRY-RUN abgeschlossen — keine Änderungen.${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
elif [ "$FAILED" = true ]; then
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  ⚠ Release v${VERSION} teilweise fehlgeschlagen!${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 1
else
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✅ Release v${VERSION} abgeschlossen!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi
