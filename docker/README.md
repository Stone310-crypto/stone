# 🐳 Stone Node – Docker

Docker-Setup um schnell Stone-Nodes zu erstellen und ein lokales Test-Netzwerk hochzufahren.

---

## Schnellstart

### Node starten (Standard: 1 Node)

```bash
# Vom Projekt-Root:
docker-compose -f docker/docker-compose.yml up --build
```

Dashboard öffnen: **http://localhost:8080**

Herunterfahren + Daten löschen:

```bash
docker-compose -f docker/docker-compose.yml down -v
```

### 3-Node Test-Cluster (optional)

```bash
docker-compose -f docker/docker-compose.yml --profile cluster up --build
```

| Node   | Dashboard            | P2P-Port |
|--------|----------------------|----------|
| Node   | http://localhost:8080 | 4001     |
| Node 2 | http://localhost:8082 | 4012     |
| Node 3 | http://localhost:8083 | 4013     |

```bash
docker-compose -f docker/docker-compose.yml --profile cluster down -v
```

---

## Umgebungsvariablen

| Variable             | Pflicht | Default | Beschreibung                                     |
|----------------------|---------|---------|--------------------------------------------------|
| `STONE_NODE_NAME`    | ✅       | –       | Name der Node                                    |
| `STONE_PASSWORD`     | ✅       | –       | Admin-Passwort (min. 8 Zeichen, Groß/Klein/Zahl/Sonderzeichen) |
| `STONE_STORAGE_GB`   | ❌       | `50`    | Angebotener Speicher in GB                       |
| `STONE_SEED_PEERS`   | ❌       | –       | Komma-separierte libp2p Multiaddrs               |
| `STONE_HTTP_PORT`    | ❌       | `8080`  | HTTP-Port (intern im Container)                  |
| `STONE_P2P_PORT`     | ❌       | `4001`  | P2P-Port (intern im Container)                   |
| `STONE_NO_SEED`      | ❌       | –       | Auf `1` setzen um eingebaute Production-Seed-Nodes zu deaktivieren |

### Seed-Peers Format

```
/ip4/192.168.1.100/tcp/4001
/dns4/stone-node1/tcp/4001
/ip4/10.0.0.5/tcp/4001/p2p/12D3KooW...
```

Mehrere Peers mit Komma trennen:

```bash
-e STONE_SEED_PEERS="/dns4/node1/tcp/4001,/dns4/node2/tcp/4001"
```

---

## Architektur

```
┌──────────────────────────────────────────────┐
│  Docker Container                            │
│                                              │
│  entrypoint.sh                               │
│    ├─ Startet stone-setup                    │
│    ├─ Konfiguriert via Setup-API:            │
│    │   POST /api/setup/password              │
│    │   POST /api/setup/node                  │
│    │   POST /api/setup/storage               │
│    │   POST /api/setup/peers                 │
│    │   POST /api/setup/finish                │
│    └─ stone-setup läuft als Full-Node        │
│                                              │
│  Ports:                                      │
│    8080 → HTTP API + Dashboard               │
│    4001 → P2P (libp2p TCP)                   │
│                                              │
│  Volume:                                     │
│    /opt/stone-node/stone_data                │
│    ├─ node_config.json                       │
│    ├─ blockchain, chunks, users, etc.        │
│    └─ keypair (Ed25519)                      │
└──────────────────────────────────────────────┘
```

---

## Erweiterte Nutzung

### Eigene Node zum Netzwerk hinzufügen

```bash
docker run -d \
  --name validator-4 \
  --network stone-docker_stonenet \
  -p 8084:8080 \
  -p 4014:4001 \
  -e STONE_NODE_NAME="validator-4" \
  -e STONE_PASSWORD="SecurePass99!" \
  -e STONE_STORAGE_GB=100 \
  -e STONE_SEED_PEERS="/dns4/stone-node1/tcp/4001" \
  stone-node
```

### Logs anschauen

```bash
# Alle Nodes
docker-compose -f docker/docker-compose.yml logs -f

# Nur Node 1
docker logs -f stone-node1
```

### Node-Status prüfen

```bash
# Health-Check
curl http://localhost:8081/api/v1/health

# Dashboard-Daten
curl http://localhost:8081/api/dashboard
```

### Daten persistieren

Die Node-Daten werden in Docker Volumes gespeichert. Um sie zu behalten:

```bash
# Normal stoppen (Volumes bleiben)
docker-compose -f docker/docker-compose.yml down

# Stoppen UND Volumes löschen
docker-compose -f docker/docker-compose.yml down -v
```

### Recovery Phrase

Beim ersten Start zeigt jeder Container die **Recovery Phrase** in den Logs:

```bash
docker logs stone-node1 2>&1 | grep -A3 "RECOVERY PHRASE"
```

> ⚠️ **Sicher aufbewahren!** Wird nur einmal angezeigt.

---

## Entwicklung

### Image neu bauen (ohne Cache)

```bash
docker build --no-cache -f docker/Dockerfile -t stone-node .
```

### In Container einloggen

```bash
docker exec -it stone-node1 /bin/bash
```

### Nur die Binaries bauen (schneller Rebuild)

Durch das Multi-Stage Dockerfile werden die Rust-Dependencies gecacht.
Nur bei Änderungen am Source Code wird neu kompiliert.

---

## Troubleshooting

| Problem | Lösung |
|---------|--------|
| `STONE_NODE_NAME muss gesetzt sein!` | `-e STONE_NODE_NAME=...` hinzufügen |
| `Passwort braucht Groß-/Kleinbuchstaben, Zahl und Sonderzeichen` | Passwort-Regeln beachten |
| Nodes finden sich nicht | Prüfen ob alle im selben Docker-Network sind |
| Build dauert ewig | Normal beim ersten Mal (Rust kompiliert ~500 Deps). Danach wird gecacht |
| Port already in use | Andere Host-Ports wählen: `-p 9080:8080` |
