#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Stone Node – Docker Entrypoint
#
# Konfiguriert die Node automatisch beim ersten Start über die Setup-API.
# Danach startet stone-setup direkt im Full-Node-Modus.
#
# Umgebungsvariablen:
#   STONE_NODE_NAME      – Name der Node (Pflicht)
#   STONE_PASSWORD       – Admin-Passwort, min 8 Zeichen (Pflicht)
#   STONE_STORAGE_GB     – Angebotener Speicher in GB (default: 50)
#   STONE_SEED_PEERS     – Komma-separierte Seed-Peer Multiaddrs
#   STONE_HTTP_PORT      – HTTP-Port (default: 8080)
#   STONE_P2P_PORT       – P2P-Port (default: 4001)
# ─────────────────────────────────────────────────────────────────────────────
set -e

NODE_NAME="${STONE_NODE_NAME:-}"
PASSWORD="${STONE_PASSWORD:-}"
STORAGE_GB="${STONE_STORAGE_GB:-50}"
SEED_PEERS="${STONE_SEED_PEERS:-}"
HTTP_PORT="${STONE_HTTP_PORT:-8080}"
P2P_PORT="${STONE_P2P_PORT:-4001}"

DATA_DIR="/opt/stone-node/stone_data"
CONFIG_FILE="/opt/stone-node/node_config.json"

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
        echo "✅ Node bereits konfiguriert → starte Full-Node..."
        export STONE_PORT="$HTTP_PORT"
        export STONE_P2P_PORT="$P2P_PORT"
        export STONE_P2P_LISTEN="/ip4/0.0.0.0/tcp/$P2P_PORT"
        export STONE_DATA_DIR="$DATA_DIR"
        exec /opt/stone-node/target/release/stone-setup
    fi
fi

# ── Erster Start: Auto-Setup via API ─────────────────────────────────────────

echo "🔧 Erster Start – konfiguriere Node '$NODE_NAME' automatisch..."

# stone-setup im Hintergrund starten (wartet auf Setup via API)
export STONE_PORT="$HTTP_PORT"
export STONE_P2P_PORT="$P2P_PORT"
export STONE_P2P_LISTEN="/ip4/0.0.0.0/tcp/$P2P_PORT"
export STONE_DATA_DIR="$DATA_DIR"

/opt/stone-node/target/release/stone-setup &
SETUP_PID=$!

# Warten bis die API erreichbar ist
echo "⏳ Warte auf Setup-API..."
for i in $(seq 1 30); do
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
curl -sf -X POST "$API/api/setup/storage" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"offered_gb\": $STORAGE_GB}" >/dev/null

# 4) Seed-Peers setzen (falls angegeben)
if [ -n "$SEED_PEERS" ]; then
    # Komma-separiert → JSON-Array
    PEERS_JSON=$(echo "$SEED_PEERS" | tr ',' '\n' | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//')
    echo "🔗 Setze Seed-Peers: $SEED_PEERS"
    curl -sf -X POST "$API/api/setup/peers" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"seed_peers\": [$PEERS_JSON]}" >/dev/null
fi

# 5) Setup abschließen → startet Full-Node im Hintergrund
echo "🚀 Schließe Setup ab..."
curl -sf -X POST "$API/api/setup/finish" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" >/dev/null

echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  ✅ Stone Node '$NODE_NAME' erfolgreich gestartet!  │"
echo "  │                                                     │"
echo "  │  🌐 Dashboard:  http://localhost:$HTTP_PORT         │"
echo "  │  📡 P2P:        /ip4/0.0.0.0/tcp/$P2P_PORT         │"
echo "  │  💾 Storage:    ${STORAGE_GB} GB                    │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""

# stone-setup läuft bereits im Hintergrund mit Full-Node
# → wir warten auf den Prozess
wait $SETUP_PID
