# StoneMC – Proof-of-Play Plugin (MVP)

Spigot/Paper-Plugin, das den Loop zwischen Minecraft und der Stonechain-Node herstellt:

```
Block-Break → Zufalls-Drop (lokal) → /stoneredeem → POST /api/v1/sdk/game/play-drop
                                                                  ↓
                                                Mempool → on-chain Transfer
```

## Komponenten

- `StoneMcPlugin` – Plugin-Entry, Commands `/stonelink`, `/stonebalance`, `/stoneredeem`.
- `BlockBreakDropListener` – `BlockBreakEvent`-Hook, schreibt lokal Pending-Balance.
- `NodeClient` – HTTP-Client gegen `/api/v1/sdk/game/play-drop`.
- `PlayerWalletStore` – JSON-Persistenz für Pending-Balance + verknüpfte Adresse.

## Bauen

```
cd plugins/stone-mc-plugin
mvn -q -DskipTests package
# Output: target/stone-mc-plugin-0.1.0-SNAPSHOT.jar
```

Alternativ (aus `plugins/`):

```
cd plugins
mvn -q -DskipTests package
# baut das Modul stone-mc-plugin über plugins/pom.xml
```

Wenn du in einem Ordner ohne `pom.xml` baust, kommt der Fehler
`MissingProjectException`.

## Setup auf der Node

1. Game registrieren (sofern noch nicht):
   ```
   POST /api/v1/sdk/game/server/add
   { "owner_mnemonic": "...", "game_id": "minecraft-pop-mvp",
     "server_pubkey": "<server-wallet-pubkey-hex-or-stone1>",
     "permissions": ["tournament"] }
   ```
2. Game-API-Key notieren (aus Quick-Register/Developer-Flow).
3. Gaming-Pool für das Spiel per Owner-Flow konfigurieren (verschlüsselt auf Node gespeichert):
   - `POST /api/v1/sdk/owner/challenge`
   - `POST /api/v1/sdk/owner/gaming-pool/configure`
4. Pool-Adresse mit etwas STONE als Treasury befüllen.
3. Optional Caps via Env (Defaults sind konservativ):
   ```
   STONE_PLAY_DAILY_GAME_CAP=1000
   STONE_PLAY_DAILY_PLAYER_CAP=50
   STONE_PLAY_PLAYER_COOLDOWN_SECS=30
   STONE_PLAY_MAX_DROP=5
   ```

## Setup im MC-Server

`plugins/StoneMC/config.yml` anpassen:

- `node_url`
- `game_id`
- `game_api_key`

Wallet-Commands im Spiel:

- `/stonelink <wallet>`: Wallet verknüpfen/überschreiben
- `/stoneunlink`: Wallet-Verknüpfung entfernen
- `/stonevault`: Persönliche Vault öffnen (nur dein Profil hat Zugriff)
- `/stoneclaim gui`: Chunk-Claim GUI oeffnen
- `/stoneclaim visual`: Claims oder aktuellen Claim visuell anzeigen
- `/stonerates`: Aktive Minecraft-Fairness-Parameter anzeigen (Drop-Rates, Shards, Limits)
- `/stonerareblock [amount]`: Admin gibt seltenen Stone Core aus
- `/smenu item`: Soulbound Stone Scroll erhalten

Personal Vault:

- Zugriff nur für den jeweiligen Spieler (profilgebunden, kein Admin-Bypass im Plugin)
- Von überall über `/smenu` oder `/stonevault` erreichbar
- Erlaubte Items: Stone Shards + eigene Stone Coins
- Inhalt wird persistent gespeichert (`plugins/StoneMC/vaults.json`)

Stone Scroll (Soulbound Menue-Item):

- Erhaltbar ueber `/smenu item` oder per Klick im `/smenu`.
- Rechtsklick mit der Scroll oeffnet direkt das Stone-Menue.
- Soulbound: nur der Owner kann sie nutzen.
- Die Scroll wird beim Tod nicht verloren und beim Respawn wiederhergestellt.

Shop:

- Shop-Preise werden mit Shards bezahlt.
- Es gibt keine zusätzliche Gebühr und keinen Shop-Treasury-Abzug.
- Shards sind reine Off-Chain-Ingame-Währung, damit das Free-to-Play-Modell erhalten bleibt.

Seltenes Spezial-Item (Stone Core):

- Sehr selten als zusätzlicher Fund beim normalen Mining.
- Platzierbarer Spezial-Block.
- Beim Abbauen ohne Silk Touch: direkter Reward von `32` Shards (konfigurierbar).
- Beim Abbauen mit Silk Touch: Block wird als Item wieder aufgehoben und kann neu platziert werden.
- Positionen platzierter Stone Cores werden persistiert (`plugins/StoneMC/rare_blocks.json`).

Wallet-Link Persistenz:

- `wallets.json` wird jetzt robuster atomar gespeichert, damit Unlink/Relink nach Restart nicht auf alte Zustände zurückfällt.

Todesschutz:

- Stone Coins **und** Stone Shards droppen beim Tod nicht und werden beim Respawn zurückgegeben.
- Shards bleiben weiterhin normal handelbar/tradbar zwischen Spielern.
- Steuerbar per Admin-Befehl (nur OP/`stone.admin`):
   - `/stonedeathprotect status`
   - `/stonedeathprotect coins on|off`
   - `/stonedeathprotect shards on|off`
- Jede Änderung wird im Server-Log mit Spielername protokolliert.

Claim-System (unabhängig vom Shop):

- Über `/smenu` oder `/stoneclaim gui` oeffnest du die Chunk-Claim-Karte.
- Claims werden direkt in der GUI pro Chunk gesetzt/entfernt.
- `/stoneclaim visual` zeigt Claim-Grenzen als Overlay.
- Andere Spieler können in fremden Claims nicht bauen/abbauen.
- Eigene Claims anzeigen: `/stoneclaim list`
- Claim unter dir: `/stoneclaim info`
- Claim entfernen: `/stoneclaim remove <id>`

Server-Owner Limits in `plugins/StoneMC/config.yml`:

- `claims.max_width`
- `claims.max_length`
- `claims.max_area`
- `claims.max_claims_per_player`

Damit kannst du die maximal erlaubte Claim-Größe global festlegen.

Alternativ per Env: `STONE_GAME_API_KEY`.

Wichtig: Wenn `STONE_GAME_API_KEY` gesetzt ist, gewinnt **immer** der Env-Wert
gegen `game_api_key` in `config.yml`.

## Server-Logs / Diagnose

Beim Plugin-Start werden jetzt zusätzliche Auth-Diagnosen geloggt:

- ob der Key aus `env:STONE_GAME_API_KEY` oder `config:game_api_key` kommt
- Key-Preview (`sk_xxx...`)
- Dashboard-Check gegen `/api/v1/sdk/developer/dashboard`

Erwartete Erfolgsmeldung:

```
StoneMC SDK auth check OK (dashboard) ...
```

Bei Fehlkonfiguration erscheint z.B.:

```
StoneMC SDK auth check FAILED (dashboard): http=403 error=Nicht autorisiert: Ungültiger API-Key ...
```

### Schnell-Diagnose (5 Zeilen)

Nach einem echten Neustart (kein `/reload`) bitte genau diese 5 Logzeilen posten:

1. `StoneMC enabled. node=... game_id=...`
2. `StoneMC auth mode: X-SDK-Key (source=...)`
3. `StoneMC effective sdk key preview: ...`
4. `StoneMC SDK auth check OK (dashboard)` **oder** `FAILED (...)`
5. Die **erste** `play-drop request failed` Zeile inklusive Ursache (falls vorhanden)

Zusatzcheck auf dem MC-Host:

- Ist `STONE_GAME_API_KEY` gesetzt, übersteuert er immer die `config.yml`.
- Runtime-Config ist `plugins/StoneMC/config.yml` auf dem MC-Server (nicht die Datei im Git-Repo).

## Bekannte MVP-Limits

- **Kein Anti-Cheat.** Auto-Mining-Bots, Macros etc. sind nicht erkannt.
- **API-Key im Config/Env.** In Produktion nur kurzlebig/rotierbar halten.
- **Pending-Balance lokal** – bei MC-Server-Datenverlust verloren. Akzeptabel für MVP.
- Caps werden node-seitig erzwungen (siehe `PlayDropTracker`).
