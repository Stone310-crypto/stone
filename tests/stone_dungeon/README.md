# Stone Dungeon — Browser Test Game

Ein kleines Browser-Spiel zum **End-to-End-Test der Game-Economy**: NFT-Minting,
Marketplace mit STONE- und USD-Listings, Oracle-Repricing, Rarity-Guard,
SDK-Auth-Flow.

## Was es macht

1. **Wallet verbinden** — Mnemonic eingeben, Adresse wird abgeleitet.
2. **Game registrieren** (einmalig pro Spiel) — erzeugt API-Key.
3. **API-Key verbinden** im Developer-Tab (Pflicht fuer realistischen Testlauf).
4. **Shop-Items** des Spiels durchsuchen, NFTs kaufen (mint).
5. **Inventar** ansehen, Items im Marketplace **in STONE oder USD** listen.
6. **Marketplace** durchsuchen und kaufen — bei USD-Listings wird der Preis
   live über den Oracle in den aktuellen STONE-Betrag umgerechnet.
7. **Live-Anzeige** des Oracle-Kurses (STONE/USD aus TestnetMarket).
8. **Warnungen** vom Rarity-Guard werden im UI angezeigt.
9. **Profilwechsel** startet Dungeon-Fortschritt profilbezogen (neues Profil bei 0).

Das Spiel selbst ist absichtlich simpel: ein Dungeon mit Klick-Combat, das
Monster spawnt, Loot droppt und alle Aktionen an die Stone-API weitergibt.

## Setup

Keine Build-Schritte. Datei direkt im Browser öffnen:

```sh
open tests/stone_dungeon/index.html
```

Oder lokal servieren (empfohlen wegen CORS):

```sh
cd tests/stone_dungeon
python3 -m http.server 8765
# → http://localhost:8765
```

## Server-URL

Im UI oben rechts wählbar:
- **Testnet** (default): `http://212.227.54.241:3080`
- **Mainnet**: `http://212.227.54.241:3180`
- **Lokal**: `http://localhost:8080`
- **Custom**: eigene URL eintragen.

## Test-Reihenfolge

1. URL wählen, Mnemonic einfügen → "Wallet laden".
2. "Game registrieren" mit beliebiger `game_id` (z.B. `dungeon-{deinName}`).
3. API-Key in das Feld "API-Key (realistischer Test)" uebernehmen oder per "API-Key verbinden" ein bestehendes Spiel laden.
4. "Shop-Item erstellen" (als Developer): z.B. *Sword*, Common, Preis 1 STONE.
5. Im **Spiel-Tab** ein Monster killen → Trigger Shop-Buy → NFT im Inventar.
6. **Im Inventar** Item zum Verkauf listen, einmal in STONE, einmal in USD.
7. In einem zweiten Browser-Tab (anderer Mnemonic) das Item kaufen.
8. Profil wechseln: neues Profil startet bei Stage 1 / Kills 0 / Loot 0.
9. **Oracle-Kurs ändern** (über Stone-Chain Trades, falls möglich) → erneut
   kaufen → USD-Preis bleibt konstant, STONE-Betrag passt sich an.
10. Rarity-Guard testen: USD-Preis weit über Limit setzen → Warnung sichtbar.
