#!/usr/bin/env bash
# ─── StoneChain Beta Airdrop Script ───────────────────────────────────
# Verteilt STONE aus einem Genesis-Pool an eine Wallet-Adresse.
#
# Verwendung:
#   ./scripts/airdrop.sh <adresse> <betrag> [pool] [memo]
#
# Beispiele:
#   ./scripts/airdrop.sh 6ab8a49a...  5000000                         # 5M aus pool:founders
#   ./scripts/airdrop.sh 6ab8a49a...  100000  pool:community "Beta Bonus"
#
# Umgebungsvariablen:
#   STONE_ADMIN_KEY  – Admin-API-Key (Pflicht)
#   STONE_SERVER     – Server-URL (Standard: http://100.90.28.68:8080)
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

ADDR="${1:?Fehler: Empfänger-Adresse fehlt}"
AMOUNT="${2:?Fehler: Betrag fehlt}"
POOL="${3:-pool:founders}"
MEMO="${4:-Beta Airdrop}"

SERVER="${STONE_SERVER:-http://100.90.28.68:8080}"
API_KEY="${STONE_ADMIN_KEY:?Fehler: STONE_ADMIN_KEY nicht gesetzt}"

echo "╔═══════════════════════════════════════╗"
echo "║     StoneChain Airdrop               ║"
echo "╠═══════════════════════════════════════╣"
echo "║  Server:  $SERVER"
echo "║  Pool:    $POOL"
echo "║  Empf.:   ${ADDR:0:16}…"
echo "║  Betrag:  $AMOUNT STONE"
echo "║  Memo:    $MEMO"
echo "╚═══════════════════════════════════════╝"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST "${SERVER}/api/v1/admin/airdrop" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${API_KEY}" \
  -d "{
    \"to\": \"${ADDR}\",
    \"amount\": \"${AMOUNT}\",
    \"from_pool\": \"${POOL}\",
    \"memo\": \"${MEMO}\"
  }")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
  echo "✅ Airdrop erfolgreich!"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
else
  echo "❌ Fehler (HTTP $HTTP_CODE):"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
  exit 1
fi
