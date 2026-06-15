# Dashboard v2 (Custom Node Dashboard API)

Dieses Dokument beschreibt das erste v2-Skeleton fuer erweiterbare Node-Dashboards.

## Ziele

- Stabile, versionierte API-Contracts fuer externe Dashboards
- Entkopplung von internen Rust-Strukturen
- Vorbereitete Berechtigungs-Scopes
- Manifest-Validation fuer Dritt-Apps

## Routen

- `GET /api/v2/dashboard/capabilities`
- `GET /api/v2/dashboard/scopes`
- `GET /api/v2/dashboard/manifest/schema`
- `POST /api/v2/dashboard/manifest/validate`
- `GET /api/v2/dashboard/widgets`
- `POST /api/v2/dashboard/widgets/install`
- `DELETE /api/v2/dashboard/widgets/{app_id}`
- `GET /api/v2/dashboard/tokens`
- `POST /api/v2/dashboard/tokens/issue`
- `POST /api/v2/dashboard/tokens/{token_id}/revoke`
- `GET /ui/dashboard-v2`

## Scope-Enforcement (aktuell)

- Alle v2 Endpunkte erwarten Authentifizierung.
- `dashboard:read` ist standardmaessig fuer authentifizierte Nutzer erlaubt.
- `admin:write` ist fuer Install/Remove erforderlich.
- Admin-Key hat implizit alle Scopes.
- Bei Requests mit `app_id` werden Scopes aus der Widget-Registry pro App ermittelt.
- Optional kann `STONE_DASHBOARD_REQUIRE_APP_ID=1` gesetzt werden, um app_id fuer alle Non-Admin-v2 Requests zu erzwingen.
- Fallback ohne app_id: globale Non-Admin-Scopes via `STONE_DASHBOARD_EXTRA_SCOPES`.
- Alternative ohne app_id Query: dedizierte Dashboard-App-Tokens (`Authorization: Bearer sd2....`).

Beispiel:

`STONE_DASHBOARD_EXTRA_SCOPES=chat:read,mining:read`

Per-App Request:

`GET /api/v2/dashboard/widgets?app_id=com.example.ops-dashboard`

## Manifest-Format (v1)

Pflichtfelder:

- `app_id`
- `name`
- `version`
- `entry_url`

Optionale Felder:

- `description`
- `author`
- `required_permissions`
- `supported_api_versions`
- `allowed_origins`
- `default_layout` (`widget_id`, `zone`, `min_w`, `min_h`)

## Beispiel-Manifest

```json
{
  "app_id": "com.example.ops-dashboard",
  "name": "Ops Dashboard",
  "version": "0.1.0",
  "entry_url": "https://dash.example.com/index.html",
  "description": "Read-only chain and node telemetry",
  "author": "Example Team",
  "required_permissions": [
    "dashboard:read",
    "metrics:read"
  ],
  "supported_api_versions": ["v2"],
  "allowed_origins": ["https://dash.example.com"],
  "default_layout": [
    { "widget_id": "node.health", "zone": "top", "min_w": 3, "min_h": 2 }
  ]
}
```

## Install-Request (Admin)

```json
{
  "manifest": {
    "app_id": "com.example.ops-dashboard",
    "name": "Ops Dashboard",
    "version": "0.1.0",
    "entry_url": "https://dash.example.com/index.html",
    "required_permissions": ["dashboard:read", "metrics:read"]
  },
  "grant_scopes": ["dashboard:read", "metrics:read"]
}
```

Hinweise:

- Wenn `grant_scopes` leer ist, werden `required_permissions` als Grants verwendet.
- `entry_url` und `allowed_origins` werden gegen die Server-Policy validiert:
  - `STONE_DASHBOARD_ALLOW_REMOTE_WIDGETS`
  - `STONE_DASHBOARD_ALLOWED_WIDGET_ORIGINS`

## Dashboard-App-Tokens (Admin)

Issue:

`POST /api/v2/dashboard/tokens/issue`

Body:

```json
{
  "app_id": "com.example.ops-dashboard",
  "scopes": ["dashboard:read", "metrics:read"],
  "ttl_secs": 86400,
  "label": "prod-ci"
}
```

Response enthaelt den Token genau einmal:

- `token_id`
- `token` (Prefix `sd2.`)
- `expires_at`

List:

`GET /api/v2/dashboard/tokens?app_id=com.example.ops-dashboard`

Revoke:

`POST /api/v2/dashboard/tokens/{token_id}/revoke`

Wichtige Env-Flags:

- `STONE_DASHBOARD_TOKEN_SECRET`
- `STONE_DASHBOARD_TOKEN_PREVIOUS_SECRET`
- `STONE_DASHBOARD_TOKEN_VERIFY_SECRETS`
- `STONE_DASHBOARD_TOKEN_TTL_SECS`

## Quickstart: Eigenes Dashboard lokal testen

Vorhandene Testdateien:

- tests/dashboard_v2/custom_dashboard/index.html
- tests/dashboard_v2/custom_dashboard/manifest.json
- scripts/test_dashboard_v2_local.sh

Empfohlener Ablauf:

1. Node starten (API erreichbar auf Port 3180).
2. Lokalen HTTP-Server laufen lassen (bei dir bereits auf Port 8765 moeglich).
3. Smoke-Test laufen lassen:

  API_KEY=$(cat stone_data/token.bin) ./scripts/test_dashboard_v2_local.sh

4. Browser-Seite oeffnen:

  http://127.0.0.1:8765/tests/dashboard_v2/custom_dashboard/index.html

5. In der Seite app_id und Token/API-Key eintragen, dann Run Smoke Test klicken.

Was der Smoke-Test macht:

- Manifest validieren
- Widget installieren
- Dashboard-App-Token ausstellen
- Capabilities mit Token pruefen
- Widgets mit Token pruefen

Token-Verify-Verhalten:

- Neue Tokens werden immer mit `STONE_DASHBOARD_TOKEN_SECRET` signiert.
- Verify akzeptiert mehrere Secrets in Reihenfolge:
  1. `STONE_DASHBOARD_TOKEN_SECRET`
  2. `STONE_DASHBOARD_TOKEN_PREVIOUS_SECRET`
  3. `STONE_DASHBOARD_TOKEN_VERIFY_SECRETS` (CSV)

Empfohlener Rotation-Runbook:

1. Neues Secret als `STONE_DASHBOARD_TOKEN_SECRET` setzen.
2. Altes Secret als `STONE_DASHBOARD_TOKEN_PREVIOUS_SECRET` setzen.
3. Node deployen/restarten.
4. Alte Tokens auslaufen lassen oder aktiv widerrufen.
5. Wenn keine alten Tokens mehr gebraucht werden: `STONE_DASHBOARD_TOKEN_PREVIOUS_SECRET` leeren.

## Scope-Katalog (aktuell)

- `dashboard:read`
- `metrics:read`
- `chat:read`
- `mining:read`
- `node:write`
- `mining:write`
- `admin:write`

## Nächste Schritte

1. Hash-Index für Token-Registry ergänzen (schneller Lookup bei grossen Token-Beständen)
2. Iframe-Sandbox + postMessage-Bridge fuer eingebettete Widgets
3. API-Versionierung absichern (v2.x compatibility contract)
4. Optional: audit-log endpoint für token issue/revoke events
