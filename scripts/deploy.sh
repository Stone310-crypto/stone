#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Stone Node Deploy Script
# 
# Cross-kompiliert auf macOS (ARM) → Linux (x86_64) und deployed per SSH.
# 
# Usage:
#   ./scripts/deploy.sh                  # Alle Nodes aus nodes.toml
#   ./scripts/deploy.sh server1          # Nur einen bestimmten Node
#   ./scripts/deploy.sh --build-only     # Nur kompilieren, nicht deployen
#   ./scripts/deploy.sh --skip-build     # Nur deployen (Binary schon gebaut)
#
# Voraussetzungen:
#   brew install zig
#   cargo install cargo-zigbuild
#   rustup target add x86_64-unknown-linux-gnu
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NODES_FILE="$PROJECT_DIR/nodes.toml"
TARGET="x86_64-unknown-linux-gnu"
BINARIES=("stone-setup" "stone-master")
RELEASE_DIR="$PROJECT_DIR/target/$TARGET/release"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Argumente parsen ─────────────────────────────────────────────────────────

BUILD=true
DEPLOY=true
SPECIFIC_NODE=""

for arg in "$@"; do
    case "$arg" in
        --build-only)  DEPLOY=false ;;
        --skip-build)  BUILD=false ;;
        --help|-h)
            echo "Usage: $0 [node-name] [--build-only] [--skip-build]"
            exit 0
            ;;
        *)  SPECIFIC_NODE="$arg" ;;
    esac
done

# ─── Version ermitteln ────────────────────────────────────────────────────────

VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_HASH=$(cd "$PROJECT_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo -e "${CYAN}  ┌─────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │${NC}  🪨  ${GREEN}Stone Node Deploy${NC}                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     v${VERSION} (${GIT_HASH})                     ${CYAN}│${NC}"
echo -e "${CYAN}  └─────────────────────────────────────────────┘${NC}"
echo ""

# ─── Cross-Compile ────────────────────────────────────────────────────────────

if [ "$BUILD" = true ]; then
    echo -e "${BLUE}[build]${NC} Cross-Compiling für $TARGET ..."
    
    # Prüfe Tools
    if ! command -v cargo-zigbuild &>/dev/null; then
        echo -e "${RED}[error]${NC} cargo-zigbuild nicht gefunden!"
        echo "  Installieren: cargo install cargo-zigbuild && brew install zig"
        exit 1
    fi

    cd "$PROJECT_DIR"
    
    for bin in "${BINARIES[@]}"; do
        echo -e "${BLUE}[build]${NC}   Kompiliere ${YELLOW}$bin${NC} ..."
        cargo zigbuild --release --target "$TARGET" --bin "$bin" 2>&1 | \
            grep -E "Compiling stone |Finished|error" || true
    done

    # Binary-Größen anzeigen
    echo ""
    for bin in "${BINARIES[@]}"; do
        SIZE=$(du -h "$RELEASE_DIR/$bin" | cut -f1)
        echo -e "${GREEN}[build]${NC}   ✅ $bin: ${SIZE}"
    done
    echo ""
fi

# ─── Nodes aus TOML lesen ────────────────────────────────────────────────────

if [ "$DEPLOY" = false ]; then
    echo -e "${GREEN}[done]${NC} Build fertig. --build-only gesetzt, kein Deploy."
    exit 0
fi

if [ ! -f "$NODES_FILE" ]; then
    echo -e "${RED}[error]${NC} $NODES_FILE nicht gefunden!"
    echo "  Erstelle die Datei (siehe nodes.toml.example)"
    exit 1
fi

# Minimaler TOML-Parser (liest [[node]] Blöcke)
deploy_to_node() {
    local name="$1"
    local host="$2"
    local user="$3"
    local port="$4"
    local path="$5"
    local service="$6"
    local bins="$7"

    echo -e "${BLUE}[deploy]${NC} → ${YELLOW}$name${NC} ($user@$host:$port)"

    # SSH-Verbindung testen
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes -p "$port" "$user@$host" "echo ok" &>/dev/null; then
        # Fallback: mit Password-Prompt
        echo -e "${YELLOW}[deploy]${NC}   SSH-Key nicht eingerichtet, verwende Password-Auth..."
    fi

    # Binaries hochladen
    for bin in $bins; do
        local src="$RELEASE_DIR/$bin"
        if [ ! -f "$src" ]; then
            echo -e "${RED}[deploy]${NC}   ⚠ Binary $bin nicht gefunden! Überspringe."
            continue
        fi

        local size=$(du -h "$src" | cut -f1)
        echo -e "${BLUE}[deploy]${NC}   📦 Uploading $bin ($size) ..."
        
        # Upload als .new, dann atomar tauschen
        scp -P "$port" -q "$src" "$user@$host:$path/$bin.new"
        
        ssh -p "$port" "$user@$host" bash -s <<REMOTE_SCRIPT
            set -e
            cd "$path"
            
            # Backup des aktuellen Binary
            if [ -f "$bin" ]; then
                cp "$bin" "$bin.bak"
            fi
            
            # Atomar tauschen
            chmod +x "$bin.new"
            mv "$bin.new" "$bin"
            
            echo "  ✅ $bin deployed"
REMOTE_SCRIPT
    done

    # Service neustarten
    if [ -n "$service" ]; then
        # Service-File aktualisieren (falls vorhanden)
        local service_src="$PROJECT_DIR/configs/stone-node.service"
        if [ -f "$service_src" ]; then
            echo -e "${BLUE}[deploy]${NC}   📄 Service-File aktualisieren..."
            scp -P "$port" -q "$service_src" "$user@$host:/etc/systemd/system/$service.service"
            ssh -p "$port" "$user@$host" "systemctl daemon-reload"
        fi

        echo -e "${BLUE}[deploy]${NC}   🔄 Restarting $service ..."
        ssh -p "$port" "$user@$host" bash -s <<REMOTE_SCRIPT
            set -e
            systemctl restart "$service"
            sleep 2
            
            if systemctl is-active --quiet "$service"; then
                echo "  ✅ $service läuft"
            else
                echo "  ❌ $service gestartet aber nicht aktiv!"
                journalctl -u "$service" --no-pager -n 10
                
                # Rollback
                cd "$path"
                for bin in $bins; do
                    if [ -f "\$bin.bak" ]; then
                        mv "\$bin.bak" "\$bin"
                    fi
                done
                systemctl restart "$service"
                echo "  ⚠ Rollback durchgeführt!"
                exit 1
            fi
REMOTE_SCRIPT
    fi
    
    echo -e "${GREEN}[deploy]${NC}   ✅ $name erfolgreich aktualisiert"
    echo ""
}

# ─── TOML parsen & deployen ──────────────────────────────────────────────────

parse_and_deploy() {
    local current_name="" current_host="" current_user="root"
    local current_port="22" current_path="" current_service=""
    local current_bins="stone-setup stone-master"
    local in_node=false

    flush_node() {
        if [ "$in_node" = true ] && [ -n "$current_name" ] && [ -n "$current_host" ]; then
            if [ -z "$SPECIFIC_NODE" ] || [ "$SPECIFIC_NODE" = "$current_name" ]; then
                deploy_to_node "$current_name" "$current_host" "$current_user" \
                    "$current_port" "$current_path" "$current_service" "$current_bins"
            fi
        fi
    }

    while IFS= read -r line || [ -n "$line" ]; do
        # Kommentare & Leerzeilen überspringen
        line=$(echo "$line" | sed 's/#.*//' | xargs)
        [ -z "$line" ] && continue

        if [[ "$line" == "[[node]]" ]]; then
            flush_node
            # Reset für neuen Node
            current_name="" current_host="" current_user="root"
            current_port="22" current_path="" current_service=""
            current_bins="stone-setup stone-master"
            in_node=true
            continue
        fi

        if [ "$in_node" = true ]; then
            key=$(echo "$line" | cut -d'=' -f1 | xargs)
            val=$(echo "$line" | cut -d'=' -f2- | xargs | sed 's/^"//;s/"$//')
            case "$key" in
                name)    current_name="$val" ;;
                host)    current_host="$val" ;;
                user)    current_user="$val" ;;
                port)    current_port="$val" ;;
                path)    current_path="$val" ;;
                service) current_service="$val" ;;
                bins)    current_bins="$val" ;;
            esac
        fi
    done < "$NODES_FILE"

    flush_node

    if [ -n "$SPECIFIC_NODE" ]; then
        # Prüfe ob der Node gefunden wurde
        local found=false
        while IFS= read -r line; do
            if echo "$line" | grep -q "name.*=.*\"$SPECIFIC_NODE\""; then
                found=true; break
            fi
        done < "$NODES_FILE"
        if [ "$found" = false ]; then
            echo -e "${RED}[error]${NC} Node '$SPECIFIC_NODE' nicht in nodes.toml gefunden!"
            echo "  Verfügbare Nodes:"
            grep 'name.*=' "$NODES_FILE" | sed 's/.*"\(.*\)".*/    - \1/'
            exit 1
        fi
    fi
}

parse_and_deploy

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✅ Deploy abgeschlossen!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
