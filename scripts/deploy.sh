#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Stone Node Deploy Script — Parallel Upload, Coordinated Restart
# 
# Cross-kompiliert auf macOS (ARM) → Linux (x86_64) und deployed per SSH.
#
# Strategie:
#   1. Cross-Compile (einmal)
#   2. Parallel Upload auf alle Nodes (als .staged) — kein Restart noch!
#   3. Warten bis ALLE Uploads fertig sind
#   4. Koordinierter Restart: alle Nodes gleichzeitig tauschen + neustarten
#   → Minimale Versions-Divergenz zwischen den Nodes
#
# Usage:
#   ./scripts/deploy.sh                  # Interaktive Auswahl: mainnet / testnet / beide
#   ./scripts/deploy.sh --mainnet        # Nur Mainnet-Nodes
#   ./scripts/deploy.sh --testnet        # Nur Testnet-Nodes
#   ./scripts/deploy.sh --all            # Beide Netzwerke
#   ./scripts/deploy.sh --mainnet server1  # Nur einen bestimmten Node
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
LOG_DIR=$(mktemp -d)

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
SEQUENTIAL=false
SPECIFIC_NODE=""
NETWORK_FILTER=""  # mainnet, testnet, all, oder leer (interaktiv)

for arg in "$@"; do
    case "$arg" in
        --build-only)   DEPLOY=false ;;
        --skip-build)   BUILD=false ;;
        --sequential)   SEQUENTIAL=true ;;
        --mainnet)      NETWORK_FILTER="mainnet" ;;
        --testnet)      NETWORK_FILTER="testnet" ;;
        --all)          NETWORK_FILTER="all" ;;
        --help|-h)
            echo "Usage: $0 [--mainnet|--testnet|--all] [node-name] [--build-only] [--skip-build]"
            echo ""
            echo "Netzwerk:"
            echo "  --mainnet     Nur Mainnet-Nodes deployen"
            echo "  --testnet     Nur Testnet-Nodes deployen"
            echo "  --all         Beide Netzwerke deployen"
            echo "  (ohne Flag)   Interaktive Auswahl"
            echo ""
            echo "Optionen:"
            echo "  node-name     Nur einen bestimmten Node deployen"
            echo "  --build-only  Nur kompilieren, nicht deployen"
            echo "  --skip-build  Nur deployen (Binary schon gebaut)"
            exit 0
            ;;
        *)  SPECIFIC_NODE="$arg" ;;
    esac
done

# ─── Interaktive Netzwerk-Auswahl ────────────────────────────────────────────

if [ "$DEPLOY" = true ] && [ -z "$NETWORK_FILTER" ]; then
    echo ""
    echo -e "${CYAN}  Welches Netzwerk deployen?${NC}"
    echo ""
    echo -e "    ${GREEN}1)${NC}  Testnet"
    echo -e "    ${GREEN}2)${NC}  Mainnet"
    echo -e "    ${GREEN}3)${NC}  Beide"
    echo ""
    read -rp "  Auswahl [1/2/3]: " choice
    case "$choice" in
        1)  NETWORK_FILTER="testnet" ;;
        2)  NETWORK_FILTER="mainnet" ;;
        3)  NETWORK_FILTER="all" ;;
        *)  echo -e "${RED}Ungültige Auswahl.${NC}"; exit 1 ;;
    esac
    echo ""
fi

# ─── Version ermitteln ────────────────────────────────────────────────────────

VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_HASH=$(cd "$PROJECT_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo -e "${CYAN}  ┌─────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │${NC}  🪨  ${GREEN}Stone Node Deploy${NC}                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     v${VERSION} (${GIT_HASH})                     ${CYAN}│${NC}"
if [ "$DEPLOY" = true ]; then
    case "$NETWORK_FILTER" in
        mainnet) echo -e "${CYAN}  │${NC}     Netzwerk: ${RED}MAINNET${NC}                     ${CYAN}│${NC}" ;;
        testnet) echo -e "${CYAN}  │${NC}     Netzwerk: ${YELLOW}TESTNET${NC}                     ${CYAN}│${NC}" ;;
        all)     echo -e "${CYAN}  │${NC}     Netzwerk: ${GREEN}MAINNET + TESTNET${NC}            ${CYAN}│${NC}" ;;
    esac
fi
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
        SIZE=$(ls -lh "$RELEASE_DIR/$bin" | awk '{print $5}')
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

# ─── Node-Daten sammeln ──────────────────────────────────────────────────────

# Arrays für alle Nodes (parallel braucht sequenziellen Zugriff)
declare -a NODE_NAMES=()
declare -a NODE_HOSTS=()
declare -a NODE_USERS=()
declare -a NODE_PORTS=()
declare -a NODE_PATHS=()
declare -a NODE_SERVICES=()
declare -a NODE_BINS=()
declare -a NODE_ROOTS=()
declare -a NODE_NETWORKS=()

parse_nodes() {
    local current_name="" current_host="" current_user="root"
    local current_port="22" current_path="" current_service=""
    local current_bins="stone-setup stone-master"
    local current_root=""
    local current_network="both"
    local in_node=false

    flush_node() {
        if [ "$in_node" = true ] && [ -n "$current_name" ] && [ -n "$current_host" ]; then
            # Name-Filter
            if [ -n "$SPECIFIC_NODE" ] && [ "$SPECIFIC_NODE" != "$current_name" ]; then
                return
            fi
            # Netzwerk-Filter
            local include=false
            case "$NETWORK_FILTER" in
                all)
                    include=true
                    ;;
                mainnet)
                    [ "$current_network" = "mainnet" ] || [ "$current_network" = "both" ] && include=true
                    ;;
                testnet)
                    [ "$current_network" = "testnet" ] || [ "$current_network" = "both" ] && include=true
                    ;;
                *)
                    include=true
                    ;;
            esac
            if [ "$include" = true ]; then
                NODE_NAMES+=("$current_name")
                NODE_HOSTS+=("$current_host")
                NODE_USERS+=("$current_user")
                NODE_PORTS+=("$current_port")
                NODE_PATHS+=("$current_path")
                NODE_SERVICES+=("$current_service")
                NODE_BINS+=("$current_bins")
                NODE_ROOTS+=("${current_root:-$current_path}")
                NODE_NETWORKS+=("$current_network")
            fi
        fi
    }

    while IFS= read -r line || [ -n "$line" ]; do
        line=$(echo "$line" | sed 's/#.*//' | xargs)
        [ -z "$line" ] && continue

        if [[ "$line" == "[[node]]" ]]; then
            flush_node
            current_name="" current_host="" current_user="root"
            current_port="22" current_path="" current_service=""
            current_bins="stone-setup stone-master"
            current_root=""
            current_network="both"
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
                root)    current_root="$val" ;;
                service) current_service="$val" ;;
                bins)    current_bins="$val" ;;
                network) current_network="$val" ;;
            esac
        fi
    done < "$NODES_FILE"

    flush_node

    if [ -n "$SPECIFIC_NODE" ] && [ ${#NODE_NAMES[@]} -eq 0 ]; then
        echo -e "${RED}[error]${NC} Node '$SPECIFIC_NODE' nicht in nodes.toml gefunden (Netzwerk: $NETWORK_FILTER)!"
        echo "  Verfügbare Nodes:"
        grep 'name.*=' "$NODES_FILE" | sed 's/.*"\(.*\)".*/    - \1/'
        exit 1
    fi
}

parse_nodes

TOTAL=${#NODE_NAMES[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo -e "${RED}[error]${NC} Keine Nodes zum Deployen gefunden."
    exit 1
fi

echo -e "${BLUE}[deploy]${NC} ${TOTAL} Node(s):"
for i in $(seq 0 $((TOTAL - 1))); do
    echo -e "  ${YELLOW}${NODE_NAMES[$i]}${NC} (${NODE_NETWORKS[$i]}) → ${NODE_HOSTS[$i]}"
done
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Phase 1: Parallel Upload (Binaries als .staged hochladen)
# ═════════════════════════════════════════════════════════════════════════════

upload_to_node() {
    local idx="$1"
    local name="${NODE_NAMES[$idx]}"
    local host="${NODE_HOSTS[$idx]}"
    local user="${NODE_USERS[$idx]}"
    local port="${NODE_PORTS[$idx]}"
    local path="${NODE_PATHS[$idx]}"
    local root="${NODE_ROOTS[$idx]}"
    local service="${NODE_SERVICES[$idx]}"
    local bins="${NODE_BINS[$idx]}"
    local network="${NODE_NETWORKS[$idx]}"
    local log="$LOG_DIR/${name}.log"

    {
        echo "[upload] → $name ($user@$host:$port)"

        # SSH-Verbindung testen
        if ! ssh -o ConnectTimeout=10 -o BatchMode=yes -p "$port" "$user@$host" "echo ok" &>/dev/null; then
            echo "[upload] ❌ SSH-Verbindung zu $name fehlgeschlagen!"
            return 1
        fi

        # Remote-Verzeichnisse erstellen falls nicht vorhanden
        local data_dir="stone_data"
        [ "$network" = "mainnet" ] && data_dir="stone_data_mainnet"
        ssh -p "$port" "$user@$host" "mkdir -p $path && mkdir -p $root/$data_dir"
        echo "[upload] ✅ Verzeichnisse erstellt ($path, $root/$data_dir)"

        # Binaries als .staged hochladen (NICHT tauschen, NICHT restarten!)
        for bin in $bins; do
            local src="$RELEASE_DIR/$bin"
            if [ ! -f "$src" ]; then
                echo "[upload] ⚠ Binary $bin nicht gefunden! Überspringe."
                continue
            fi

            local size=$(ls -lh "$src" | awk '{print $5}')
            echo "[upload] 📦 $bin ($size) → $name ..."

            scp -P "$port" -C -q "$src" "$user@$host:$path/$bin.staged"
            ssh -p "$port" "$user@$host" "chmod +x $path/$bin.staged"
            echo "[upload] ✅ $bin staged auf $name"
        done

        # Service-File vorbereiten (staged)
        local service_src="$PROJECT_DIR/configs/stone-node.service"
        if [ -n "$service" ] && [ -f "$service_src" ]; then
            local tmp_service="/tmp/stone-node-${name}.service"
            sed -e "s|__STONE_ROOT__|$root|g" -e "s|__STONE_PATH__|$path|g" -e "s|__STONE_NETWORK__|$network|g" "$service_src" > "$tmp_service"
            scp -P "$port" -q "$tmp_service" "$user@$host:/tmp/stone-node.service.staged"
            rm -f "$tmp_service"
            echo "[upload] ✅ Service-File staged auf $name"
        fi

        # announcements.json (Founder-Pubkeys) synchronisieren
        local ann_src="$PROJECT_DIR/stone_data/announcements.json"
        if [ -f "$ann_src" ]; then
            scp -P "$port" -q "$ann_src" "$user@$host:$root/$data_dir/announcements.json"
            echo "[upload] ✅ announcements.json synchronisiert auf $name ($data_dir)"
        fi

        # .env mit netzwerk-spezifischen Ports erstellen/aktualisieren
        if [ "$network" = "mainnet" ]; then
            ssh -p "$port" "$user@$host" "printf 'STONE_NETWORK=mainnet\nSTONE_DATA_DIR=./stone_data_mainnet\nSTONE_P2P_PORT=5001\nSTONE_P2P_LISTEN=/ip4/0.0.0.0/tcp/5001\n' > $root/.env && echo OK"
            echo "[upload] ✅ .env für mainnet auf $name"
        fi

        echo "[upload] ✅ $name bereit für Restart"
    } > "$log" 2>&1

    return $?
}

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Phase 1: Parallel Upload${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Alle Uploads parallel starten
UPLOAD_PIDS=()
for i in $(seq 0 $((TOTAL - 1))); do
    echo -e "${BLUE}[upload]${NC} Starte Upload → ${YELLOW}${NODE_NAMES[$i]}${NC} (${NODE_HOSTS[$i]}) ..."
    upload_to_node "$i" &
    UPLOAD_PIDS+=($!)
done

# Auf ALLE Uploads warten
echo ""
echo -e "${BLUE}[upload]${NC} Warte auf ${TOTAL} parallele Uploads ..."
UPLOAD_FAILED=false
for i in $(seq 0 $((TOTAL - 1))); do
    local_name="${NODE_NAMES[$i]}"
    local_pid="${UPLOAD_PIDS[$i]}"
    if wait "$local_pid"; then
        echo -e "${GREEN}[upload]${NC} ✅ ${local_name} — Upload fertig"
    else
        echo -e "${RED}[upload]${NC} ❌ ${local_name} — Upload fehlgeschlagen!"
        UPLOAD_FAILED=true
    fi
    # Log ausgeben
    if [ -f "$LOG_DIR/${local_name}.log" ]; then
        sed 's/^/    /' "$LOG_DIR/${local_name}.log"
    fi
done

echo ""

if [ "$UPLOAD_FAILED" = true ]; then
    echo -e "${RED}[error]${NC} Mindestens ein Upload fehlgeschlagen!"
    echo -e "${RED}[error]${NC} Staged Binaries auf erfolgreichen Nodes aufräumen ..."
    for i in $(seq 0 $((TOTAL - 1))); do
        ssh -o ConnectTimeout=5 -p "${NODE_PORTS[$i]}" "${NODE_USERS[$i]}@${NODE_HOSTS[$i]}" \
            "rm -f ${NODE_PATHS[$i]}/*.staged /tmp/stone-node.service.staged" 2>/dev/null || true
    done
    echo -e "${RED}[error]${NC} Abgebrochen. Kein Node wurde neugestartet."
    rm -rf "$LOG_DIR"
    exit 1
fi

echo -e "${GREEN}[upload]${NC} ✅ Alle ${TOTAL} Nodes haben Binaries empfangen"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Phase 2: Koordinierter Restart (alle gleichzeitig)
# ═════════════════════════════════════════════════════════════════════════════

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Phase 2: Koordinierter Restart${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Schritt 2a: Atomar tauschen auf ALLEN Nodes (parallel, ohne Restart)
swap_on_node() {
    local idx="$1"
    local name="${NODE_NAMES[$idx]}"
    local host="${NODE_HOSTS[$idx]}"
    local user="${NODE_USERS[$idx]}"
    local port="${NODE_PORTS[$idx]}"
    local path="${NODE_PATHS[$idx]}"
    local service="${NODE_SERVICES[$idx]}"
    local bins="${NODE_BINS[$idx]}"

    ssh -p "$port" "$user@$host" bash -s -- "$path" "$service" "$bins" <<'SWAP_SCRIPT'
        set -e
        PATH_DIR="$1"
        SERVICE="$2"
        shift 2
        BINS="$*"
        cd "$PATH_DIR"

        # Backup + Atomar tauschen
        for bin in $BINS; do
            if [ -f "$bin.staged" ]; then
                [ -f "$bin" ] && cp "$bin" "$bin.bak"
                mv "$bin.staged" "$bin"
            fi
        done

        # Service-File tauschen + bei Erstinstallation aktivieren
        if [ -n "$SERVICE" ] && [ -f /tmp/stone-node.service.staged ]; then
            FIRST_INSTALL=false
            if [ ! -f "/etc/systemd/system/${SERVICE}.service" ]; then
                FIRST_INSTALL=true
            fi
            mv /tmp/stone-node.service.staged "/etc/systemd/system/${SERVICE}.service"
            systemctl daemon-reload
            if [ "$FIRST_INSTALL" = true ]; then
                systemctl enable "$SERVICE" 2>/dev/null || true
                echo "SERVICE_ENABLED"
            fi
        fi

        echo "SWAP_OK"
SWAP_SCRIPT
}

echo -e "${BLUE}[swap]${NC} Tausche Binaries auf allen Nodes gleichzeitig ..."

SWAP_PIDS=()
SWAP_RESULTS=()
for i in $(seq 0 $((TOTAL - 1))); do
    swap_on_node "$i" > "$LOG_DIR/${NODE_NAMES[$i]}_swap.log" 2>&1 &
    SWAP_PIDS+=($!)
done

SWAP_OK=true
for i in $(seq 0 $((TOTAL - 1))); do
    if wait "${SWAP_PIDS[$i]}"; then
        echo -e "${GREEN}[swap]${NC}   ✅ ${NODE_NAMES[$i]} — Binaries getauscht"
    else
        echo -e "${RED}[swap]${NC}   ❌ ${NODE_NAMES[$i]} — Swap fehlgeschlagen!"
        SWAP_OK=false
    fi
done

if [ "$SWAP_OK" != true ]; then
    echo -e "${RED}[error]${NC} Swap fehlgeschlagen auf mindestens einem Node!"
    echo -e "${YELLOW}[info]${NC}  Services wurden NICHT neugestartet. Manueller Eingriff nötig."
    rm -rf "$LOG_DIR"
    exit 1
fi

echo ""

# Schritt 2b: Restart ALLE Services gleichzeitig
restart_node() {
    local idx="$1"
    local name="${NODE_NAMES[$idx]}"
    local host="${NODE_HOSTS[$idx]}"
    local user="${NODE_USERS[$idx]}"
    local port="${NODE_PORTS[$idx]}"
    local path="${NODE_PATHS[$idx]}"
    local service="${NODE_SERVICES[$idx]}"
    local bins="${NODE_BINS[$idx]}"
    local network="${NODE_NETWORKS[$idx]}"
    local log="$LOG_DIR/${name}_restart.log"

    {
        if [ -z "$service" ]; then
            echo "[restart] $name — kein Service konfiguriert, überspringe"
            return 0
        fi

        echo "[restart] 🔄 $name — systemctl restart $service ..."
        ssh -p "$port" "$user@$host" bash -s -- "$service" "$path" "$network" "$bins" <<'RESTART_SCRIPT'
            set -e
            SERVICE="$1"
            BIN_PATH="$2"
            NETWORK="$3"
            shift 3
            BINS="$*"

            # Ports je nach Netzwerk
            if [ "$NETWORK" = "mainnet" ]; then
                P2P_PORT=5001
                HTTP_PORT=3180
            else
                P2P_PORT=4001
                HTTP_PORT=3080
            fi

            # Sicherstellen dass systemd die Service-Datei kennt
            systemctl daemon-reload

            # Erstinstallation: Service aktivieren falls noch nicht enabled
            if ! systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
                if [ -f "/etc/systemd/system/${SERVICE}.service" ]; then
                    systemctl enable "$SERVICE"
                    echo "✅ $SERVICE erstmalig aktiviert"
                else
                    echo "❌ Service-Datei /etc/systemd/system/${SERVICE}.service nicht gefunden!"
                    exit 1
                fi
            fi

            # Pre-restart Cleanup: Stop + verwaiste Prozesse aus diesem BIN_PATH töten.
            # Grund: stone-setup forkt stone-master als Child; wenn der Parent durch
            # systemctl SIGTERM stirbt, kann der Child manchmal überleben und Port 8080
            # weiterhin halten → "Address already in use" beim Neustart.
            # Wir filtern strikt nach BIN_PATH, damit das andere Netz (z.B. mainnet
            # unter /home/mainnet) auf demselben Server NICHT angefasst wird.
            systemctl stop "$SERVICE" 2>/dev/null || true
            for proc in stone-setup stone-master; do
                # pkill -f matched gegen die volle Cmdline; BIN_PATH/proc trifft nur
                # diesen Node, nicht das andere Netz.
                pkill -TERM -f "${BIN_PATH}/${proc}" 2>/dev/null || true
            done
            # Kurz warten und ggf. SIGKILL nachschieben, falls etwas hängt.
            sleep 2
            for proc in stone-setup stone-master; do
                pkill -KILL -f "${BIN_PATH}/${proc}" 2>/dev/null || true
            done

            systemctl restart "$SERVICE"
            sleep 3

            if systemctl is-active --quiet "$SERVICE"; then
                echo "✅ $SERVICE läuft ($NETWORK)"

                # Health-Checks
                sleep 2
                if command -v ss &>/dev/null; then
                    if ss -tlnp 2>/dev/null | grep -q ":$P2P_PORT "; then
                        echo "✅ P2P-Port $P2P_PORT lauscht"
                    else
                        echo "⚠ P2P-Port $P2P_PORT noch nicht bereit"
                    fi
                fi
                if command -v curl &>/dev/null; then
                    if curl -sf -o /dev/null --max-time 5 http://127.0.0.1:$HTTP_PORT/api/v1/health 2>/dev/null; then
                        echo "✅ HTTP-API erreichbar (Port $HTTP_PORT)"
                    else
                        echo "⚠ HTTP-API noch nicht erreichbar (Port $HTTP_PORT)"
                    fi
                fi
            else
                echo "❌ $SERVICE nicht aktiv! Rollback ..."
                journalctl -u "$SERVICE" --no-pager -n 15
                cd "$BIN_PATH"
                for bin in $BINS; do
                    if [ -f "$bin.bak" ]; then
                        mv "$bin.bak" "$bin"
                    fi
                done
                systemctl restart "$SERVICE"
                echo "⚠ Rollback durchgeführt"
                exit 1
            fi
RESTART_SCRIPT
        echo "[restart] ✅ $name — online"
    } > "$log" 2>&1

    return $?
}

echo -e "${BLUE}[restart]${NC} Starte alle ${TOTAL} Services gleichzeitig ..."

RESTART_PIDS=()
for i in $(seq 0 $((TOTAL - 1))); do
    restart_node "$i" &
    RESTART_PIDS+=($!)
done

# Auf alle Restarts warten
ALL_OK=true
for i in $(seq 0 $((TOTAL - 1))); do
    local_name="${NODE_NAMES[$i]}"
    if wait "${RESTART_PIDS[$i]}"; then
        echo -e "${GREEN}[restart]${NC} ✅ ${local_name} — online"
    else
        echo -e "${RED}[restart]${NC} ❌ ${local_name} — Restart fehlgeschlagen (Rollback aktiv)"
        ALL_OK=false
    fi
    if [ -f "$LOG_DIR/${local_name}_restart.log" ]; then
        sed 's/^/    /' "$LOG_DIR/${local_name}_restart.log"
    fi
done

echo ""

# Aufräumen
rm -rf "$LOG_DIR"

# ─── Ergebnis ─────────────────────────────────────────────────────────────────

if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✅ Deploy abgeschlossen! Alle ${TOTAL} Nodes auf v${VERSION}${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  ⚠ Deploy teilweise fehlgeschlagen! Logs prüfen.${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 1
fi
