#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Stone Node – Docker Entrypoint
#
# Konfiguriert die Node automatisch beim ersten Start über die Setup-API.
# Danach startet stone-setup direkt im Full-Node-Modus.
#
# Umgebungsvariablen:
#   STONE_NETWORK        – Netzwerk: "testnet" (default) oder "mainnet"
#   STONE_NODE_NAME      – Name der Node (Pflicht)
#   STONE_PASSWORD       – Admin-Passwort, min 8 Zeichen (Pflicht)
#   STONE_STORAGE_GB     – Angebotener Speicher in GB (default: 50)
#   STONE_SEED_PEERS     – Komma-separierte Seed-Peer Multiaddrs
#   STONE_HTTP_PORT      – HTTP-Port (default: 8080)
#   STONE_P2P_PORT       – P2P-Port (default: 4001 testnet, 5001 mainnet)
#   STONE_ADMIN_KEY      – Separater Admin-Key (optional, empfohlen)
#   STONE_VALIDATOR_PASSPHRASE – Passphrase für Validator-Key-Verschlüsselung
# ─────────────────────────────────────────────────────────────────────────────
set -e

# ── Docker-Kennung setzen (damit der Updater es erkennt) ─────────────────────
export STONE_DOCKER=1

NODE_NAME="${STONE_NODE_NAME:-}"
PASSWORD="${STONE_PASSWORD:-}"
STORAGE_GB="${STONE_STORAGE_GB:-50}"
NETWORK="${STONE_NETWORK:-testnet}"

# Netzwerk-abhängige Defaults
if [ "$NETWORK" = "mainnet" ] || [ "$NETWORK" = "main" ]; then
    DEFAULT_HTTP_PORT="8180"
    DEFAULT_P2P_PORT="5001"
    DEFAULT_SEEDS="/ip4/212.227.54.241/tcp/5001/p2p/12D3KooWNz9GTNsFks567mHaQLKR4Ai6MCiw5WUDWAgvny1ow4tJ,/ip4/212.227.54.241/udp/5001/quic-v1/p2p/12D3KooWNz9GTNsFks567mHaQLKR4Ai6MCiw5WUDWAgvny1ow4tJ"
else
    DEFAULT_HTTP_PORT="8080"
    DEFAULT_P2P_PORT="4001"
    DEFAULT_SEEDS="/ip4/212.227.54.241/tcp/4001/p2p/12D3KooWNz9GTNsFks567mHaQLKR4Ai6MCiw5WUDWAgvny1ow4tJ,/ip4/212.227.54.241/udp/4001/quic-v1/p2p/12D3KooWNz9GTNsFks567mHaQLKR4Ai6MCiw5WUDWAgvny1ow4tJ"
fi

SEED_PEERS="${STONE_SEED_PEERS:-$DEFAULT_SEEDS}"
HTTP_PORT="${STONE_HTTP_PORT:-$DEFAULT_HTTP_PORT}"
P2P_PORT="${STONE_P2P_PORT:-$DEFAULT_P2P_PORT}"

DATA_DIR="/opt/stone-node/stone_data"
BINARY="/opt/stone-node/target/release/stone-setup"
UPDATE_BINARY="$DATA_DIR/updates/stone-setup"

# ── Arbeitsverzeichnis = Volume ──────────────────────────────────────────────
# stone-setup schreibt node_config.json ins CWD. Damit die Config bei Restarts
# erhalten bleibt, setzen wir CWD auf das gemountete Volume.
mkdir -p "$DATA_DIR"
cd "$DATA_DIR"

CONFIG_FILE="$DATA_DIR/node_config.json"

# ── OTA-Update: Prüfe ob ein neues Binary auf dem Volume liegt ───────────────

if [ -f "$UPDATE_BINARY" ] && [ -x "$UPDATE_BINARY" ]; then
    # Versionsprüfung: Neues Binary muss lauffähig sein
    if "$UPDATE_BINARY" --version >/dev/null 2>&1 || true; then
        echo "🔄 OTA-Update gefunden → installiere neues Binary..."
        cp "$BINARY" "${BINARY}.bak" 2>/dev/null || true
        cp "$UPDATE_BINARY" "$BINARY"
        chmod 755 "$BINARY"
        rm -f "$UPDATE_BINARY"
        echo "✅ Update installiert – starte mit neuer Version"
    else
        echo "⚠️  Update-Binary nicht lauffähig → ignoriert"
        rm -f "$UPDATE_BINARY"
    fi
fi

# ── Prüfungen ────────────────────────────────────────────────────────────────

if [ -z "$NODE_NAME" ]; then
    echo "❌ STONE_NODE_NAME muss gesetzt sein!"
    echo "   Beispiel: -e STONE_NODE_NAME=mein-node"
    exit 1
fi

if [ -z "$PASSWORD" ]; then
    echo "❌ STONE_PASSWORD muss gesetzt sein!"
    echo "   Mindestens 8 Zeichen mit Groß-/Kleinbuchstaben, Zahl und Sonderzeichen"
    exit 1
fi

# ── Bereits konfiguriert? ────────────────────────────────────────────────────

if [ -f "$CONFIG_FILE" ]; then
    SETUP_DONE=$(grep -o '"setup_complete":true' "$CONFIG_FILE" 2>/dev/null || echo "")
    if [ -n "$SETUP_DONE" ]; then
        echo "✅ Node bereits konfiguriert ($NETWORK) → starte Full-Node..."
        export STONE_NETWORK="$NETWORK"
        export STONE_PORT="$HTTP_PORT"
        export STONE_P2P_PORT="$P2P_PORT"
        export STONE_P2P_LISTEN="/ip4/0.0.0.0/tcp/$P2P_PORT"
        export STONE_DATA_DIR="$DATA_DIR"
        # QUIC lauscht automatisch auf demselben Port (UDP)
        exec "$BINARY"
    fi
fi

# ── Erster Start: Auto-Setup via API ─────────────────────────────────────────

echo "🔧 Erster Start – konfiguriere Node '$NODE_NAME' automatisch..."

# stone-setup im Hintergrund starten (wartet auf Setup via API)
export STONE_NETWORK="$NETWORK"
export STONE_PORT="$HTTP_PORT"
export STONE_P2P_PORT="$P2P_PORT"
export STONE_P2P_LISTEN="/ip4/0.0.0.0/tcp/$P2P_PORT"
export STONE_DATA_DIR="$DATA_DIR"

/opt/stone-node/target/release/stone-setup &
SETUP_PID=$!

# Warten bis die API erreichbar ist
echo "⏳ Warte auf Setup-API..."
for i in $(seq 1 60); do
    if curl -sf "http://localhost:$HTTP_PORT/api/status" >/dev/null 2>&1; then
        echo "✅ Setup-API erreichbar"
        break
    fi
    if ! kill -0 $SETUP_PID 2>/dev/null; then
        echo "❌ stone-setup unerwartet beendet!"
        exit 1
    fi
    sleep 1
done

API="http://localhost:$HTTP_PORT"

# 1) Passwort setzen
echo "🔑 Setze Passwort..."
RESULT=$(curl -sf -X POST "$API/api/setup/password" \
    -H "Content-Type: application/json" \
    -d "{\"password\": \"$PASSWORD\"}" 2>&1)
TOKEN=$(echo "$RESULT" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
    echo "⚠️  Passwort-Response: $RESULT"
fi

# 2) Node-Name + Wallet generieren
echo "📛 Setze Node-Name: $NODE_NAME"
RESULT=$(curl -sf -X POST "$API/api/setup/node" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"node_name\": \"$NODE_NAME\"}" 2>&1)
WALLET=$(echo "$RESULT" | grep -o '"wallet_address":"[^"]*"' | cut -d'"' -f4)
MNEMONIC=$(echo "$RESULT" | grep -o '"mnemonic":"[^"]*"' | cut -d'"' -f4)
echo "💰 Wallet: ${WALLET:0:16}..."
if [ -n "$MNEMONIC" ]; then
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║  🔐 RECOVERY PHRASE – SICHER AUFBEWAHREN!               ║"
    echo "  ╠══════════════════════════════════════════════════════════╣"
    echo "  ║  $MNEMONIC"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo ""
fi

# 3) Storage konfigurieren
echo "💾 Setze Storage: ${STORAGE_GB} GB"
curl -sf --max-time 10 -X POST "$API/api/setup/storage" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"offered_gb\": $STORAGE_GB}" >/dev/null || echo "⚠️  Storage-Konfiguration fehlgeschlagen (nicht kritisch)"

# 4) Seed-Peers setzen (falls angegeben)
if [ -n "$SEED_PEERS" ]; then
    # Komma-separiert → JSON-Array
    PEERS_JSON=$(echo "$SEED_PEERS" | tr ',' '\n' | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//')
    echo "🔗 Setze Seed-Peers..."
    curl -sf --max-time 10 -X POST "$API/api/setup/peers" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"seed_peers\": [$PEERS_JSON]}" >/dev/null || echo "⚠️  Seed-Peers fehlgeschlagen (nicht kritisch)"
fi

# 5) Setup abschließen → startet Full-Node im Hintergrund
echo "🚀 Schließe Setup ab..."
curl -sf --max-time 10 -X POST "$API/api/setup/finish" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" >/dev/null || echo "⚠️  Finish-Call fehlgeschlagen"

echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  ✅ Stone Node '$NODE_NAME' erfolgreich gestartet!  │"
echo "  │                                                     │"
echo "  │  🌐 Dashboard:  http://localhost:$HTTP_PORT         │"
echo "  │  📡 P2P TCP:    /ip4/0.0.0.0/tcp/$P2P_PORT         │"
echo "  │  🚀 P2P QUIC:   /ip4/0.0.0.0/udp/$P2P_PORT/quic-v1 │"
echo "  │  💾 Storage:    ${STORAGE_GB} GB                    │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""

# stone-setup läuft bereits im Hintergrund mit Full-Node
# → wir warten auf den Prozess. Falls er sich beendet (z.B. Transition
#   Setup→Full-Node), starten wir ihn neu im Full-Node-Modus.
wait $SETUP_PID || true

# Falls stone-setup sich nach finish beendet hat → im Full-Node-Modus neu starten
if [ -f "$CONFIG_FILE" ]; then
    echo "🔄 Starte Full-Node-Modus..."
    exec "$BINARY"
fi
