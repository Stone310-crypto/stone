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

# WS-A Gates: Preflight + Post-Deploy-Konvergenz
MIN_FREE_MB="${STONE_DEPLOY_MIN_FREE_MB:-1024}"
MAX_CLOCK_SKEW_SECS="${STONE_DEPLOY_MAX_CLOCK_SKEW_SECS:-120}"
POSTCHECK_RETRIES="${STONE_DEPLOY_POSTCHECK_RETRIES:-6}"
POSTCHECK_INTERVAL_SECS="${STONE_DEPLOY_POSTCHECK_INTERVAL_SECS:-5}"
POSTCHECK_GLOBAL_RETRIES="${STONE_DEPLOY_POSTCHECK_GLOBAL_RETRIES:-12}"
POSTCHECK_GLOBAL_INTERVAL_SECS="${STONE_DEPLOY_POSTCHECK_GLOBAL_INTERVAL_SECS:-5}"
POSTCHECK_MAINNET_MAX_DIFF="${STONE_DEPLOY_POSTCHECK_MAINNET_MAX_DIFF:-5}"
POSTCHECK_TESTNET_MAX_DIFF="${STONE_DEPLOY_POSTCHECK_TESTNET_MAX_DIFF:-15}"
POSTCHECK_REQUIRE_SINGLE_HEAD="${STONE_DEPLOY_POSTCHECK_REQUIRE_SINGLE_HEAD:-0}"
STRICT_SEED_CHECK="${STONE_DEPLOY_STRICT_SEED_CHECK:-0}"
REQUIRE_STAGE4_AUTO_RECOVERY="${STONE_DEPLOY_REQUIRE_STAGE4_AUTO_RECOVERY:-0}"
REJECT_RECOVERY_STAGES="${STONE_DEPLOY_REJECT_RECOVERY_STAGES:-1}"
REQUIRE_RECOVERY_STATUS="${STONE_DEPLOY_REQUIRE_RECOVERY_STATUS:-0}"
REQUIRE_SETUP_COMPLETE="${STONE_DEPLOY_REQUIRE_SETUP_COMPLETE:-1}"
SYNC_OTA_TRUST_KEY="${STONE_DEPLOY_SYNC_OTA_TRUST_KEY:-1}"
AUTO_UPDATE_ENABLED="${STONE_DEPLOY_AUTO_UPDATE_ENABLED:-1}"
AUTO_UPDATE_HOUR="${STONE_DEPLOY_AUTO_UPDATE_HOUR:-4}"
MAINNET_P2P_PORT="${STONE_DEPLOY_MAINNET_P2P_PORT:-5003}"
CHAT_BATCH_MIN_MESSAGES="${STONE_DEPLOY_CHAT_BATCH_MIN_MESSAGES:-20}"
CHAT_BATCH_MAX_WAIT_SECS="${STONE_DEPLOY_CHAT_BATCH_MAX_WAIT_SECS:-10}"

OTA_TRUSTED_KEY="${STONE_UPDATE_TRUSTED_KEY:-}"
if [ -z "$OTA_TRUSTED_KEY" ]; then
    for candidate in \
        "$PROJECT_DIR/keys/update_signing.pub" \
        "$PROJECT_DIR/update_signing.pub" \
        "$PROJECT_DIR/scripts/keys/update_signing.pub"
    do
        if [ -f "$candidate" ]; then
            OTA_TRUSTED_KEY="$(tr -d '[:space:]' < "$candidate")"
            break
        fi
    done
fi

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

if [ "$SYNC_OTA_TRUST_KEY" = "1" ]; then
    if [ -n "$OTA_TRUSTED_KEY" ]; then
        echo -e "${BLUE}[ota]${NC} Trusted Update Key wird auf Ziel-Nodes synchronisiert"
        if [ "$AUTO_UPDATE_ENABLED" = "1" ]; then
            echo -e "${BLUE}[ota]${NC} Auto-Update-Fenster: ${YELLOW}${AUTO_UPDATE_HOUR}:00${NC}"
        else
            echo -e "${YELLOW}[ota]${NC} Auto-Install deaktiviert (STONE_DEPLOY_AUTO_UPDATE_ENABLED=0)"
        fi
        echo ""
    else
        echo -e "${YELLOW}[ota]${NC} Kein Trusted Update Key gefunden – OTA-Trust wird nicht provisioniert"
        echo ""
    fi
fi

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

TESTNET_SEED_NODES_ENV=""
TESTNET_BOOTSTRAP_HTTP_ENV=""
MAINNET_SEED_NODES_ENV=""
MAINNET_BOOTSTRAP_HTTP_ENV=""

append_csv_unique() {
    local current="$1"
    local value="$2"
    if [ -z "$value" ]; then
        echo "$current"
        return
    fi
    case ",$current," in
        *",$value,"*) echo "$current" ;;
        ",,"|",") echo "$value" ;;
        *) echo "$current,$value" ;;
    esac
}

seed_nodes_env_for_network() {
    local network="$1"
    if [ "$network" = "mainnet" ]; then
        echo "$MAINNET_SEED_NODES_ENV"
    else
        echo "$TESTNET_SEED_NODES_ENV"
    fi
}

bootstrap_http_env_for_network() {
    local network="$1"
    if [ "$network" = "mainnet" ]; then
        echo "$MAINNET_BOOTSTRAP_HTTP_ENV"
    else
        echo "$TESTNET_BOOTSTRAP_HTTP_ENV"
    fi
}

collect_live_bootstrap_metadata() {
    local discovered=0
    local mainnet_discovered=0
    local testnet_discovered=0

    for i in $(seq 0 $((TOTAL - 1))); do
        local host="${NODE_HOSTS[$i]}"
        local user="${NODE_USERS[$i]}"
        local port="${NODE_PORTS[$i]}"
        local network="${NODE_NETWORKS[$i]}"
        local http_port="3080"
        local p2p_port="4001"
        if [ "$network" = "mainnet" ]; then
            http_port="3180"
            p2p_port="$MAINNET_P2P_PORT"
        fi

        local peer_id
        peer_id=$(ssh -o ConnectTimeout=8 -o BatchMode=yes -p "$port" "$user@$host" \
            "curl -sf --max-time 5 http://127.0.0.1:${http_port}/api/v1/p2p/status | tr -d '\n' | sed -n 's/.*\"local_peer_id\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p'" \
            2>/dev/null || true)

        if [ -z "$peer_id" ]; then
            echo -e "${YELLOW}[bootstrap]${NC} ⚠ ${NODE_NAMES[$i]}: lokale PeerId via /api/v1/p2p/status nicht lesbar"
            continue
        fi

        local tcp_addr="/ip4/${host}/tcp/${p2p_port}/p2p/${peer_id}"
        local quic_addr="/ip4/${host}/udp/${p2p_port}/quic-v1/p2p/${peer_id}"
        local http_url="http://${host}:${http_port}"

        if [ "$network" = "mainnet" ]; then
            MAINNET_SEED_NODES_ENV=$(append_csv_unique "$MAINNET_SEED_NODES_ENV" "$tcp_addr")
            MAINNET_SEED_NODES_ENV=$(append_csv_unique "$MAINNET_SEED_NODES_ENV" "$quic_addr")
            MAINNET_BOOTSTRAP_HTTP_ENV=$(append_csv_unique "$MAINNET_BOOTSTRAP_HTTP_ENV" "$http_url")
            mainnet_discovered=$((mainnet_discovered + 1))
        else
            TESTNET_SEED_NODES_ENV=$(append_csv_unique "$TESTNET_SEED_NODES_ENV" "$tcp_addr")
            TESTNET_SEED_NODES_ENV=$(append_csv_unique "$TESTNET_SEED_NODES_ENV" "$quic_addr")
            TESTNET_BOOTSTRAP_HTTP_ENV=$(append_csv_unique "$TESTNET_BOOTSTRAP_HTTP_ENV" "$http_url")
            testnet_discovered=$((testnet_discovered + 1))
        fi
        discovered=$((discovered + 1))
    done

    if [ "$discovered" -gt 0 ]; then
        echo -e "${GREEN}[bootstrap]${NC} Live-Bootstrap-Metadaten gesammelt: total=${discovered} testnet=${testnet_discovered} mainnet=${mainnet_discovered}"
    else
        echo -e "${YELLOW}[bootstrap]${NC} Keine Live-Bootstrap-Metadaten gesammelt – bestehende Seed-Konfiguration bleibt aktiv"
    fi
}

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

# ─── WS-A: Preflight-Gates ───────────────────────────────────────────────────

testnet_count=0
mainnet_count=0
for i in $(seq 0 $((TOTAL - 1))); do
    if [ "${NODE_NETWORKS[$i]}" = "mainnet" ]; then
        mainnet_count=$((mainnet_count + 1))
    else
        testnet_count=$((testnet_count + 1))
    fi
done

required_peers_for_network() {
    local network="$1"
    local count=0
    if [ "$network" = "mainnet" ]; then
        count="$mainnet_count"
    else
        count="$testnet_count"
    fi
    if [ "$count" -le 1 ]; then
        echo 0
    else
        echo 1
    fi
}

validate_local_binaries() {
    local missing=0
    for i in $(seq 0 $((TOTAL - 1))); do
        for bin in ${NODE_BINS[$i]}; do
            if [ ! -f "$RELEASE_DIR/$bin" ]; then
                echo -e "${RED}[preflight]${NC} ❌ Lokale Binary fehlt: $RELEASE_DIR/$bin"
                missing=1
            fi
        done
    done
    if [ "$missing" -eq 1 ]; then
        echo -e "${RED}[error]${NC} Fehlende Binaries. Entweder bauen oder --skip-build entfernen."
        exit 1
    fi
}

check_seed_reachability() {
    local host="$1"
    local user="$2"
    local port="$3"
    local network="$4"
    local seed_port="4001"
    if [ "$network" = "mainnet" ]; then
        seed_port="$MAINNET_P2P_PORT"
    fi
        # Built-in Seed-IP-Adressen (gleiche Hosts wie im Rust-Code)
        ssh -p "$port" "$user@$host" bash -s -- "$seed_port" <<'SEEDCHECK' 2>/dev/null || echo "0"
seed_port="$1"
ok=0
if command -v nc >/dev/null 2>&1; then
    for ip in 212.227.54.241 69.48.200.255; do
        if nc -z -w 3 "$ip" "$seed_port" >/dev/null 2>&1; then
            ok=1
            break
        fi
    done
fi
echo "$ok"
SEEDCHECK
}

preflight_on_node() {
    local idx="$1"
    local name="${NODE_NAMES[$idx]}"
    local host="${NODE_HOSTS[$idx]}"
    local user="${NODE_USERS[$idx]}"
    local port="${NODE_PORTS[$idx]}"
    local path="${NODE_PATHS[$idx]}"
    local root="${NODE_ROOTS[$idx]}"
    local service="${NODE_SERVICES[$idx]}"
    local network="${NODE_NETWORKS[$idx]}"
    local log="$LOG_DIR/${name}_preflight.log"

    {
        echo "[preflight] → $name ($user@$host:$port)"

        if ! ssh -o ConnectTimeout=10 -o BatchMode=yes -p "$port" "$user@$host" "echo ok" &>/dev/null; then
            echo "[preflight] ❌ SSH-Verbindung fehlgeschlagen"
            exit 1
        fi

        local local_epoch remote_epoch skew
        local_epoch=$(date +%s)
        remote_epoch=$(ssh -p "$port" "$user@$host" "date +%s" 2>/dev/null || echo "0")
        if [ "$remote_epoch" -le 0 ]; then
            echo "[preflight] ❌ Remote-Zeit konnte nicht gelesen werden"
            exit 1
        fi
        if [ "$remote_epoch" -ge "$local_epoch" ]; then
            skew=$((remote_epoch - local_epoch))
        else
            skew=$((local_epoch - remote_epoch))
        fi
        if [ "$skew" -gt "$MAX_CLOCK_SKEW_SECS" ]; then
            echo "[preflight] ❌ Clock-Skew zu hoch: ${skew}s (max ${MAX_CLOCK_SKEW_SECS}s)"
            exit 1
        fi
        echo "[preflight] ✅ Clock-Skew: ${skew}s"

        ssh -p "$port" "$user@$host" bash -s -- "$root" "$path" "$service" "$network" "$MIN_FREE_MB" "$REQUIRE_STAGE4_AUTO_RECOVERY" "$REQUIRE_SETUP_COMPLETE" "$MAINNET_P2P_PORT" <<'PREFLIGHT_REMOTE'
set -e
ROOT="$1"
PATH_DIR="$2"
SERVICE="$3"
NETWORK="$4"
MIN_MB="$5"
    REQUIRE_STAGE4="$6"
    REQUIRE_SETUP_COMPLETE="$7"
    MAINNET_P2P_PORT="$8"

mkdir -p "$ROOT" "$PATH_DIR"

if [ -n "$SERVICE" ] && ! command -v systemctl >/dev/null 2>&1; then
    echo "[preflight] ❌ systemctl fehlt, Service-Deploy nicht möglich"
    exit 1
fi

FREE_MB=$(df -Pm "$ROOT" | awk 'NR==2 {print $4}')
if [ -z "$FREE_MB" ] || [ "$FREE_MB" -lt "$MIN_MB" ]; then
    echo "[preflight] ❌ Zu wenig freier Speicher unter $ROOT: ${FREE_MB:-0}MB (min ${MIN_MB}MB)"
    exit 1
fi
echo "[preflight] ✅ Freier Speicher: ${FREE_MB}MB"

if [ -f "$ROOT/.env" ]; then
    if ! grep -q '^STONE_P2P_PORT=' "$ROOT/.env"; then
        echo "[preflight] ⚠ .env vorhanden, aber STONE_P2P_PORT fehlt"
    fi

    # WS-C Stage4-Sicherheits-Gate:
    # Wenn aktiviert, erzwingen wir Auto-Snapshot-Recovery um einen
    # "stummen" Stage4-Zustand ohne Selbstheilung zu vermeiden.
    stage4_enabled=$(grep '^STONE_SYNC_RECOVERY_STAGE4=' "$ROOT/.env" | tail -1 | cut -d'=' -f2- || true)
    auto_recovery=$(grep '^STONE_SYNC_AUTO_SNAPSHOT_RECOVERY=' "$ROOT/.env" | tail -1 | cut -d'=' -f2- || true)
    [ -z "$stage4_enabled" ] && stage4_enabled="(default=1)"
    [ -z "$auto_recovery" ] && auto_recovery="(default=0)"

    if [ "$REQUIRE_STAGE4" = "1" ]; then
        if ! grep -q '^STONE_SYNC_AUTO_SNAPSHOT_RECOVERY=1$' "$ROOT/.env"; then
            echo "[preflight] ❌ Stage4-Gate aktiv, aber STONE_SYNC_AUTO_SNAPSHOT_RECOVERY=1 fehlt in $ROOT/.env"
            echo "[preflight]    Aktuell: STONE_SYNC_RECOVERY_STAGE4=${stage4_enabled}, STONE_SYNC_AUTO_SNAPSHOT_RECOVERY=${auto_recovery}"
            exit 1
        fi
        echo "[preflight] ✅ Stage4-Gate: Auto-Snapshot-Recovery aktiv"
    else
        if grep -q '^STONE_SYNC_RECOVERY_STAGE4=1$' "$ROOT/.env" && ! grep -q '^STONE_SYNC_AUTO_SNAPSHOT_RECOVERY=1$' "$ROOT/.env"; then
            echo "[preflight] ⚠ Stage4 ist aktiv, aber Auto-Snapshot-Recovery ist aus"
            echo "[preflight]   Empfehlung: STONE_SYNC_AUTO_SNAPSHOT_RECOVERY=1 setzen"
        fi
    fi
else
    if [ "$REQUIRE_STAGE4" = "1" ]; then
        echo "[preflight] ❌ Stage4-Gate aktiv, aber $ROOT/.env fehlt"
        exit 1
    fi
    echo "[preflight] ⚠ $ROOT/.env fehlt – Stage4-Konfig konnte nicht geprüft werden"
fi

CONFIG_FILE="$ROOT/node_config.json"
if [ -f "$CONFIG_FILE" ]; then
    setup_complete=$(tr -d '\n' < "$CONFIG_FILE" | sed -n 's/.*"setup_complete"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p')
    node_name=$(tr -d '\n' < "$CONFIG_FILE" | sed -n 's/.*"node_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [ -z "$setup_complete" ] && setup_complete="unknown"
    if [ "$setup_complete" = "true" ]; then
        echo "[preflight] ✅ node_config.json: setup_complete=true${node_name:+ (node=$node_name)}"
    else
        if [ "$REQUIRE_SETUP_COMPLETE" = "1" ]; then
            echo "[preflight] ❌ node_config.json ist nicht betriebsbereit: setup_complete=${setup_complete}"
            echo "[preflight]    $CONFIG_FILE hält stone-setup sonst im Wizard-Modus fest"
            exit 1
        fi
        echo "[preflight] ⚠ node_config.json: setup_complete=${setup_complete}"
    fi
else
    if [ "$REQUIRE_SETUP_COMPLETE" = "1" ]; then
        echo "[preflight] ❌ $CONFIG_FILE fehlt – stone-setup würde nur die Setup-UI starten"
        exit 1
    fi
    echo "[preflight] ⚠ $CONFIG_FILE fehlt"
fi

if command -v ss >/dev/null 2>&1; then
    if [ "$NETWORK" = "mainnet" ]; then
        P2P_PORT="$MAINNET_P2P_PORT"
        HTTP_PORT=3180
    else
        P2P_PORT=4001
        HTTP_PORT=3080
    fi
    if ss -tln 2>/dev/null | grep -q ":$P2P_PORT "; then
        echo "[preflight] ✅ P2P-Port $P2P_PORT lauscht bereits"
    else
        echo "[preflight] ⚠ P2P-Port $P2P_PORT lauscht aktuell nicht"
    fi
    if ss -tln 2>/dev/null | grep -q ":$HTTP_PORT "; then
        echo "[preflight] ✅ HTTP-Port $HTTP_PORT lauscht bereits"
    else
        echo "[preflight] ⚠ HTTP-Port $HTTP_PORT lauscht aktuell nicht"
    fi
fi
PREFLIGHT_REMOTE

        seed_ok=$(check_seed_reachability "$host" "$user" "$port" "$network")
        if [ "$seed_ok" = "1" ]; then
            echo "[preflight] ✅ Mindestens ein Seed erreichbar"
        else
            if [ "$STRICT_SEED_CHECK" = "1" ]; then
                echo "[preflight] ❌ Kein Seed erreichbar (STRICT aktiv)"
                exit 1
            fi
            echo "[preflight] ⚠ Kein Seed via nc erreichbar (Warnung, kein Hard-Fail)"
        fi

        echo "[preflight] ✅ $name bestanden"
    } > "$log" 2>&1
}

postcheck_on_node() {
    local idx="$1"
    local name="${NODE_NAMES[$idx]}"
    local host="${NODE_HOSTS[$idx]}"
    local user="${NODE_USERS[$idx]}"
    local port="${NODE_PORTS[$idx]}"
    local network="${NODE_NETWORKS[$idx]}"
    local min_peers
    min_peers=$(required_peers_for_network "$network")
    local http_port="3080"
    if [ "$network" = "mainnet" ]; then
        http_port="3180"
    fi
    local log="$LOG_DIR/${name}_postcheck.log"

    {
        echo "[postcheck] → $name ($network)"
        ssh -p "$port" "$user@$host" bash -s -- "$http_port" "$min_peers" "$POSTCHECK_RETRIES" "$POSTCHECK_INTERVAL_SECS" "$REJECT_RECOVERY_STAGES" "$REQUIRE_RECOVERY_STATUS" <<'POSTCHECK_REMOTE'
set -e
HTTP_PORT="$1"
MIN_PEERS="$2"
RETRIES="$3"
INTERVAL="$4"
    REJECT_STAGES="$5"
    REQUIRE_RECOVERY="$6"

attempt=1
while [ "$attempt" -le "$RETRIES" ]; do
    health_ok=0
    peers=-1
    chain=-1
    tip_index=-1
    tip_hash=""
    recovery_stage="unknown"
    recovery_ok=1
    setup_complete="unknown"
    setup_node_name=""

    if curl -sf --max-time 5 "http://127.0.0.1:${HTTP_PORT}/api/v1/health" >/dev/null 2>&1; then
        health_ok=1
    fi

    setup_json=$(curl -sf --max-time 5 "http://127.0.0.1:${HTTP_PORT}/api/status" 2>/dev/null || true)
    if [ -n "$setup_json" ]; then
        setup_complete=$(echo "$setup_json" | tr -d '\n' | sed -n 's/.*"setup_complete"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p')
        setup_node_name=$(echo "$setup_json" | tr -d '\n' | sed -n 's/.*"node_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        [ -z "$setup_complete" ] && setup_complete="unknown"
    fi

    status_json=$(curl -sf --max-time 5 "http://127.0.0.1:${HTTP_PORT}/api/v1/p2p/status" 2>/dev/null || true)
    tip_json=$(curl -sf --max-time 5 "http://127.0.0.1:${HTTP_PORT}/api/v1/spv/tip" 2>/dev/null || true)
    if [ -n "$status_json" ]; then
        peers=$(echo "$status_json" | tr -d '\n' | sed -n 's/.*"connected_peers"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
        chain=$(echo "$status_json" | tr -d '\n' | sed -n 's/.*"chain_block_count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
        recovery_stage=$(echo "$status_json" | tr -d '\n' | sed -n 's/.*"sync_recovery"[[:space:]]*:[[:space:]]*{[^}]*"stage"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        [ -z "$peers" ] && peers=-1
        [ -z "$chain" ] && chain=-1
        [ -z "$recovery_stage" ] && recovery_stage="unknown"

        if [ "$REQUIRE_RECOVERY" = "1" ] && [ "$recovery_stage" = "unknown" ]; then
            recovery_ok=0
        fi

        if [ "$REJECT_STAGES" = "1" ]; then
            if [ "$recovery_stage" = "stage3_rebuild_network" ] || [ "$recovery_stage" = "stage4_snapshot_escalation" ]; then
                recovery_ok=0
            fi
        fi
    fi
    if [ -n "$tip_json" ]; then
        tip_index=$(echo "$tip_json" | tr -d '\n' | sed -n 's/.*"index"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
        tip_hash=$(echo "$tip_json" | tr -d '\n' | sed -n 's/.*"hash"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{64\}\)".*/\1/p')
        if [ -n "$tip_index" ]; then
            chain=$((tip_index + 1))
        fi
    fi

    if [ "$health_ok" -eq 1 ] && [ "$peers" -ge "$MIN_PEERS" ] && [ "$recovery_ok" -eq 1 ]; then
        echo "POSTCHECK_OK connected=$peers chain=$chain recovery_stage=$recovery_stage tip_hash=${tip_hash:-unknown}"
        exit 0
    fi

    echo "[postcheck] Versuch ${attempt}/${RETRIES}: health=${health_ok} connected=${peers} min=${MIN_PEERS} chain=${chain} recovery_stage=${recovery_stage} recovery_ok=${recovery_ok} setup_complete=${setup_complete}${setup_node_name:+ node=${setup_node_name}}"

    if [ "$setup_complete" = "false" ]; then
        echo "POSTCHECK_FAIL setup_incomplete"
        exit 1
    fi

    attempt=$((attempt + 1))
    sleep "$INTERVAL"
done

echo "POSTCHECK_FAIL health_connectivity_or_recovery"
exit 1
POSTCHECK_REMOTE
    } > "$log" 2>&1
}

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Phase 0: Preflight-Gates${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

validate_local_binaries

PREFLIGHT_PIDS=()
for i in $(seq 0 $((TOTAL - 1))); do
    echo -e "${BLUE}[preflight]${NC} Prüfe ${YELLOW}${NODE_NAMES[$i]}${NC} ..."
    preflight_on_node "$i" &
    PREFLIGHT_PIDS+=($!)
done

PREFLIGHT_FAILED=false
for i in $(seq 0 $((TOTAL - 1))); do
    local_name="${NODE_NAMES[$i]}"
    if wait "${PREFLIGHT_PIDS[$i]}"; then
        echo -e "${GREEN}[preflight]${NC} ✅ ${local_name}"
    else
        echo -e "${RED}[preflight]${NC} ❌ ${local_name}"
        PREFLIGHT_FAILED=true
    fi
    if [ -f "$LOG_DIR/${local_name}_preflight.log" ]; then
        sed 's/^/    /' "$LOG_DIR/${local_name}_preflight.log"
    fi
done
echo ""

if [ "$PREFLIGHT_FAILED" = true ]; then
    echo -e "${RED}[error]${NC} Preflight fehlgeschlagen. Deploy wird abgebrochen."
    rm -rf "$LOG_DIR"
    exit 1
fi

collect_live_bootstrap_metadata
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
    local seed_nodes_env
    local bootstrap_http_env
    seed_nodes_env=$(seed_nodes_env_for_network "$network")
    bootstrap_http_env=$(bootstrap_http_env_for_network "$network")
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
            local tmp_service
            tmp_service="$(mktemp "${TMPDIR:-/tmp}/stone-node-${name}.XXXXXX.service")"
            local remote_service_stage="/tmp/stone-node-${service}.service.staged"
            sed -e "s|__STONE_ROOT__|$root|g" -e "s|__STONE_PATH__|$path|g" -e "s|__STONE_NETWORK__|$network|g" "$service_src" > "$tmp_service"
            scp -P "$port" -q "$tmp_service" "$user@$host:$remote_service_stage"
            rm -f "$tmp_service"
            echo "[upload] ✅ Service-File staged auf $name"
        fi

        # announcements.json (Founder-Pubkeys) synchronisieren
        local ann_src="$PROJECT_DIR/stone_data/announcements.json"
        if [ -f "$ann_src" ]; then
            scp -P "$port" -q "$ann_src" "$user@$host:$root/$data_dir/announcements.json"
            echo "[upload] ✅ announcements.json synchronisiert auf $name ($data_dir)"
        fi

        if [ "$SYNC_OTA_TRUST_KEY" = "1" ] && [ -n "$OTA_TRUSTED_KEY" ]; then
            ssh -p "$port" "$user@$host" bash -s -- "$root/$data_dir/trusted_update_keys.txt" "$OTA_TRUSTED_KEY" <<'OTA_KEYS'
set -e
KEY_FILE="$1"
TRUSTED_KEY="$2"
mkdir -p "$(dirname "$KEY_FILE")"
touch "$KEY_FILE"
if ! grep -qx "$TRUSTED_KEY" "$KEY_FILE" 2>/dev/null; then
    printf '%s\n' "$TRUSTED_KEY" >> "$KEY_FILE"
fi
OTA_KEYS
            echo "[upload] ✅ trusted_update_keys.txt aktualisiert auf $name ($data_dir)"
        fi

        # .env mit netzwerk-spezifischen Werten aktualisieren, aber bestehende
        # Variablen (API-Keys, Update-Keys, Recovery-Flags, Public-IP, etc.) erhalten.
        ssh -p "$port" "$user@$host" bash -s -- "$root/.env" "$network" "$OTA_TRUSTED_KEY" "$AUTO_UPDATE_ENABLED" "$AUTO_UPDATE_HOUR" "$seed_nodes_env" "$bootstrap_http_env" "$MAINNET_P2P_PORT" "$CHAT_BATCH_MIN_MESSAGES" "$CHAT_BATCH_MAX_WAIT_SECS" <<'NODE_ENV'
set -e
ENV_FILE="$1"
NETWORK="$2"
OTA_TRUSTED_KEY="$3"
AUTO_UPDATE_ENABLED="$4"
AUTO_UPDATE_HOUR="$5"
    SEED_NODES_ENV="$6"
    BOOTSTRAP_HTTP_ENV="$7"
    MAINNET_P2P_PORT="$8"
    CHAT_BATCH_MIN_MESSAGES="$9"
    CHAT_BATCH_MAX_WAIT_SECS="${10}"
TMP_FILE="${ENV_FILE}.tmp"
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
cp "$ENV_FILE" "$TMP_FILE"

set_kv() {
    key="$1"
    value="$2"
    if grep -q "^${key}=" "$TMP_FILE"; then
        sed -i.bak "s|^${key}=.*|${key}=${value}|" "$TMP_FILE"
        rm -f "${TMP_FILE}.bak"
    else
        printf '%s=%s\n' "$key" "$value" >> "$TMP_FILE"
    fi
}

if [ "$NETWORK" = "mainnet" ]; then
    set_kv "STONE_NETWORK" "mainnet"
    set_kv "STONE_DATA_DIR" "./stone_data_mainnet"
    set_kv "STONE_P2P_PORT" "$MAINNET_P2P_PORT"
    set_kv "STONE_P2P_LISTEN" "/ip4/0.0.0.0/tcp/$MAINNET_P2P_PORT"
    set_kv "STONE_DASHBOARD_PORT" "8080"
    set_kv "STONE_PORT" "3180"
    set_kv "STONE_HTTP_PORT" "3180"
    set_kv "STONE_SYNC_PORT" "5002"
else
    set_kv "STONE_NETWORK" "testnet"
    set_kv "STONE_DATA_DIR" "./stone_data"
    set_kv "STONE_P2P_PORT" "4001"
    set_kv "STONE_P2P_LISTEN" "/ip4/0.0.0.0/tcp/4001"
    set_kv "STONE_PORT" "3080"
    set_kv "STONE_HTTP_PORT" "3080"
    set_kv "STONE_SYNC_PORT" "4002"
fi

if [ -n "$SEED_NODES_ENV" ]; then
    set_kv "STONE_SEED_NODES" "$SEED_NODES_ENV"
    if [ "$NETWORK" = "mainnet" ]; then
        set_kv "STONE_NO_SEED" "1"
    fi
fi

if [ -n "$BOOTSTRAP_HTTP_ENV" ]; then
    set_kv "STONE_BOOTSTRAP_NODES" "$BOOTSTRAP_HTTP_ENV"
fi

if [ -n "$OTA_TRUSTED_KEY" ]; then
    set_kv "STONE_UPDATE_TRUSTED_KEY" "$OTA_TRUSTED_KEY"
fi

if [ "$AUTO_UPDATE_ENABLED" = "1" ]; then
    set_kv "STONE_AUTO_UPDATE" "1"
fi

if [ -n "$AUTO_UPDATE_HOUR" ]; then
    set_kv "STONE_AUTO_UPDATE_HOUR" "$AUTO_UPDATE_HOUR"
fi

if [ -n "$CHAT_BATCH_MIN_MESSAGES" ]; then
    set_kv "STONE_CHAT_BATCH_MIN_MESSAGES" "$CHAT_BATCH_MIN_MESSAGES"
fi

if [ -n "$CHAT_BATCH_MAX_WAIT_SECS" ]; then
    set_kv "STONE_CHAT_BATCH_MAX_WAIT_SECS" "$CHAT_BATCH_MAX_WAIT_SECS"
fi

mv "$TMP_FILE" "$ENV_FILE"
NODE_ENV
        echo "[upload] ✅ .env / OTA-Konfig aktualisiert auf $name"

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
            "rm -f ${NODE_PATHS[$i]}/*.staged /tmp/stone-node-*.service.staged" 2>/dev/null || true
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

        # Service-File tauschen + bei Erstinstallation aktivieren
        # (Binary-Swap passiert NACH systemctl stop im Restart-Schritt → kein "Text file busy")
        SERVICE_STAGE="/tmp/stone-node-${SERVICE}.service.staged"
        if [ -n "$SERVICE" ] && [ -f "$SERVICE_STAGE" ]; then
            FIRST_INSTALL=false
            if [ ! -f "/etc/systemd/system/${SERVICE}.service" ]; then
                FIRST_INSTALL=true
            fi
            mv "$SERVICE_STAGE" "/etc/systemd/system/${SERVICE}.service"
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
        ssh -p "$port" "$user@$host" bash -s -- "$service" "$path" "$network" "$MAINNET_P2P_PORT" "$bins" <<'RESTART_SCRIPT'
            set -e
            SERVICE="$1"
            BIN_PATH="$2"
            NETWORK="$3"
            MAINNET_P2P_PORT="$4"
            shift 4
            BINS="$*"

            # Ports je nach Netzwerk
            if [ "$NETWORK" = "mainnet" ]; then
                P2P_PORT="$MAINNET_P2P_PORT"
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

            # Binary-Swap NACH dem Stop: Prozess ist jetzt down → kein "Text file busy".
            cd "$BIN_PATH"
            for bin in $BINS; do
                if [ -f "$bin.staged" ]; then
                    [ -f "$bin" ] && cp "$bin" "$bin.bak"
                    mv "$bin.staged" "$bin"
                    sync
                fi
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

# ═════════════════════════════════════════════════════════════════════════════
# Phase 3: Post-Deploy-Konvergenzcheck
# ═════════════════════════════════════════════════════════════════════════════

if [ "$ALL_OK" = true ]; then
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Phase 3: Post-Deploy-Konvergenzcheck${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    POSTCHECK_PIDS=()
    for i in $(seq 0 $((TOTAL - 1))); do
        echo -e "${BLUE}[postcheck]${NC} Prüfe ${YELLOW}${NODE_NAMES[$i]}${NC} ..."
        postcheck_on_node "$i" &
        POSTCHECK_PIDS+=($!)
    done

    POSTCHECK_FAILED=false

    for i in $(seq 0 $((TOTAL - 1))); do
        local_name="${NODE_NAMES[$i]}"
        if wait "${POSTCHECK_PIDS[$i]}"; then
            echo -e "${GREEN}[postcheck]${NC} ✅ ${local_name}"
        else
            echo -e "${RED}[postcheck]${NC} ❌ ${local_name}"
            POSTCHECK_FAILED=true
        fi

        if [ -f "$LOG_DIR/${local_name}_postcheck.log" ]; then
            sed 's/^/    /' "$LOG_DIR/${local_name}_postcheck.log"
        fi
    done

    run_global_convergence_eval() {
        chain_min_mainnet=""
        chain_max_mainnet=0
        chain_count_mainnet=0
        tip_hashes_mainnet=""
        chain_min_testnet=""
        chain_max_testnet=0
        chain_count_testnet=0
        tip_hashes_testnet=""

        for i in $(seq 0 $((TOTAL - 1))); do
            local_name="${NODE_NAMES[$i]}"
            host="${NODE_HOSTS[$i]}"
            user="${NODE_USERS[$i]}"
            port="${NODE_PORTS[$i]}"
            net="${NODE_NETWORKS[$i]}"
            http_port="3080"
            if [ "$net" = "mainnet" ]; then
                http_port="3180"
            fi

            line=$(ssh -o ConnectTimeout=8 -o BatchMode=yes -p "$port" "$user@$host" \
                "tip=\$(curl -sf --max-time 5 http://127.0.0.1:${http_port}/api/v1/spv/tip 2>/dev/null || true); \
                 idx=\$(echo \"\$tip\" | tr -d '\\n' | sed -n 's/.*\"index\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p'); \
                 h=\$(echo \"\$tip\" | tr -d '\\n' | sed -n 's/.*\"hash\"[[:space:]]*:[[:space:]]*\"\\([a-f0-9]\\{64\\}\\)\".*/\\1/p'); \
                 if [ -n \"\$idx\" ]; then c=\$((idx+1)); echo \"chain=\$c tip_hash=\${h:-unknown}\"; fi" \
                2>/dev/null || true)

            chain=$(echo "$line" | sed -n 's/.*chain=\([0-9][0-9]*\).*/\1/p')
            tip_hash=$(echo "$line" | sed -n 's/.*tip_hash=\([a-f0-9]\{64\}\).*/\1/p')
            if [ -n "$chain" ]; then
                if [ "$net" = "mainnet" ]; then
                    if [ -z "$chain_min_mainnet" ] || [ "$chain" -lt "$chain_min_mainnet" ]; then
                        chain_min_mainnet="$chain"
                    fi
                    if [ "$chain" -gt "$chain_max_mainnet" ]; then
                        chain_max_mainnet="$chain"
                    fi
                    chain_count_mainnet=$((chain_count_mainnet + 1))
                    if [ -n "$tip_hash" ] && ! printf '%b' "$tip_hashes_mainnet" | grep -qx "$tip_hash"; then
                        tip_hashes_mainnet+="${tip_hash}"$'\n'
                    fi
                else
                    if [ -z "$chain_min_testnet" ] || [ "$chain" -lt "$chain_min_testnet" ]; then
                        chain_min_testnet="$chain"
                    fi
                    if [ "$chain" -gt "$chain_max_testnet" ]; then
                        chain_max_testnet="$chain"
                    fi
                    chain_count_testnet=$((chain_count_testnet + 1))
                    if [ -n "$tip_hash" ] && ! printf '%b' "$tip_hashes_testnet" | grep -qx "$tip_hash"; then
                        tip_hashes_testnet+="${tip_hash}"$'\n'
                    fi
                fi
            fi
        done

        local convergence_failed=false

        # Konvergenz-Gate: netzwerkspezifische Diff-Schwellen.
        # Tip-Hash-Unanimity ist optional, da bei aktivem Mining kurzzeitig
        # unterschiedliche Heads auftreten können.
        if [ "$chain_count_mainnet" -ge 2 ] && [ -n "$chain_min_mainnet" ]; then
            diff_mainnet=$((chain_max_mainnet - chain_min_mainnet))
            if [ "$diff_mainnet" -gt "$POSTCHECK_MAINNET_MAX_DIFF" ]; then
                echo -e "${RED}[postcheck]${NC} ❌ Mainnet nicht konvergent (diff=${diff_mainnet}, max=${POSTCHECK_MAINNET_MAX_DIFF})"
                convergence_failed=true
            else
                echo -e "${GREEN}[postcheck]${NC} ✅ Mainnet konvergent (diff=${diff_mainnet})"
            fi
            unique_mainnet_hashes=$(printf '%b' "$tip_hashes_mainnet" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
            if [ "$unique_mainnet_hashes" -gt 1 ]; then
                if [ "$POSTCHECK_REQUIRE_SINGLE_HEAD" = "1" ]; then
                    echo -e "${RED}[postcheck]${NC} ❌ Mainnet Tip-Hash divergent (${unique_mainnet_hashes} verschiedene Heads)"
                    convergence_failed=true
                else
                    echo -e "${YELLOW}[postcheck]${NC} ⚠ Mainnet Tip-Hash divergent (${unique_mainnet_hashes} verschiedene Heads, toleriert)"
                fi
            fi
        fi
        if [ "$chain_count_testnet" -ge 2 ] && [ -n "$chain_min_testnet" ]; then
            diff_testnet=$((chain_max_testnet - chain_min_testnet))
            if [ "$diff_testnet" -gt "$POSTCHECK_TESTNET_MAX_DIFF" ]; then
                echo -e "${RED}[postcheck]${NC} ❌ Testnet nicht konvergent (diff=${diff_testnet}, max=${POSTCHECK_TESTNET_MAX_DIFF})"
                convergence_failed=true
            else
                echo -e "${GREEN}[postcheck]${NC} ✅ Testnet konvergent (diff=${diff_testnet})"
            fi
            unique_testnet_hashes=$(printf '%b' "$tip_hashes_testnet" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
            if [ "$unique_testnet_hashes" -gt 1 ]; then
                if [ "$POSTCHECK_REQUIRE_SINGLE_HEAD" = "1" ]; then
                    echo -e "${RED}[postcheck]${NC} ❌ Testnet Tip-Hash divergent (${unique_testnet_hashes} verschiedene Heads)"
                    convergence_failed=true
                else
                    echo -e "${YELLOW}[postcheck]${NC} ⚠ Testnet Tip-Hash divergent (${unique_testnet_hashes} verschiedene Heads, toleriert)"
                fi
            fi
        fi

        if [ "$convergence_failed" = true ]; then
            return 1
        fi
        return 0
    }

    if [ "$POSTCHECK_FAILED" = false ]; then
        global_try=1
        global_ok=false
        while [ "$global_try" -le "$POSTCHECK_GLOBAL_RETRIES" ]; do
            echo -e "${BLUE}[postcheck]${NC} Globaler Konvergenzcheck Versuch ${global_try}/${POSTCHECK_GLOBAL_RETRIES} ..."
            if run_global_convergence_eval; then
                global_ok=true
                break
            fi
            global_try=$((global_try + 1))
            if [ "$global_try" -le "$POSTCHECK_GLOBAL_RETRIES" ]; then
                sleep "$POSTCHECK_GLOBAL_INTERVAL_SECS"
            fi
        done
        if [ "$global_ok" = false ]; then
            POSTCHECK_FAILED=true
        fi
    fi

    if [ "$POSTCHECK_FAILED" = true ]; then
        ALL_OK=false
    fi
    echo ""
fi

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
