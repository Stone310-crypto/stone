# Stone — Dezentrale Blockchain-Plattform

Stone ist eine eigenständige Blockchain mit integrierter Token-Ökonomie, P2P-Netzwerk, verschlüsseltem Chat, Staking, Governance und Game-SDK. Ein einziger Node bringt alles mit — von Mining über Wallet-Management bis zu atomaren Swaps.

**Mainnet** und **Testnet** laufen parallel auf getrennten Ports und Datenverzeichnissen.

---

## Inhaltsverzeichnis

1. [Architektur](#architektur)
2. [Features](#features)
3. [Schnellstart](#schnellstart)
4. [Netzwerk-Konfiguration (Mainnet / Testnet)](#netzwerk-konfiguration)
5. [Umgebungsvariablen](#umgebungsvariablen)
6. [Binaries & Tools](#binaries--tools)
7. [API-Übersicht (150+ Endpunkte)](#api-übersicht)
8. [Authentifizierung](#authentifizierung)
9. [Docker Deployment](#docker-deployment)
10. [Projektstruktur](#projektstruktur)
11. [Technologie-Stack](#technologie-stack)

---

## Architektur

```
                        ┌──────────────────────────────────────────────┐
                        │              Stone Node                      │
                        │                                              │
  iOS / Android App ───►│  Axum REST API + WebSocket                   │
  StoneScan Explorer ──►│    ├── Token Ledger (RocksDB)                │
  Miner Clients ───────►│    ├── Blockchain (RocksDB)                  │
                        │    ├── Chat (E2E verschlüsselt)              │
                        │    ├── Staking Pool                          │
                        │    ├── HTLC (Atomic Swaps)                   │
                        │    ├── Bridge (Wrapped Tokens)               │
                        │    ├── Game SDK (NFTs, Marketplace)          │
                        │    └── Governance (Dual-Vote)                │
                        │                                              │
                        │  libp2p P2P (TCP + QUIC)                     │
                        │    ├── Gossipsub (Blocks, Mempool, Chat)     │
                        │    ├── Kademlia DHT                          │
                        │    ├── Relay + DCUtR (NAT-Traversal)         │
                        │    └── OTA Updates (signiert, via Gossip)    │
                        │                                              │
                        │  Datenspeicher                               │
                        │    ├── chain_db/   (RocksDB – Blöcke)        │
                        │    ├── token_db/   (RocksDB – Konten)        │
                        │    ├── chunks/     (Content-Addressed Files)  │
                        │    └── snapshots/  (Zstd-komprimiert)        │
                        └──────────────────────────────────────────────┘
```

---

## Features

### Token-Ökonomie

- **StoneCoin (STONE)** — 50M Genesis-Supply, 8 Dezimalstellen, Bech32m-Adressen (`stone1...`)
- **Mining** — Intervall-basiert (30s Block-Target), Halving-Schema für Block-Rewards
- **Staking** — PoS-Pool (min. 100 STONE, 7-Tage Unstake-Lock, 720-Block Epochs, 30% Fee-Redistribution)
- **Mempool** — Thread-sichere TX-Queue mit Nonce-Prüfung, TTL, Rate-Limiting
- **Fee-Tiers** — Priority (0.001), Standard (0.0001), Low (0.00001)

### Governance & Konsensus

- **Proof-of-Authority (PoA)** — Validator-Whitelist mit Ed25519-Signaturen, Supermajority (⌊2/3⌋+1)
- **Dual-Vote Governance** — 50% Node-Voting + 50% Stake-Voting (verhindert Zentralisierung)
- **Multisig Bootstrap** — Kritische Parameter benötigen 3-of-5 Signaturen + Governance-Vote
- **Web-of-Trust** — Peer-Reputation, Join-Requests, 30-Tage Uptime, Slashing

### Kommunikation

- **E2E-Chat** — AES-256-GCM via ECDH, Merkle-Batch Anchoring auf der Chain
- **Organisationen** — Rollen (Owner/Admin/Member/Viewer), Channels, Dokumentenfreigabe
- **Push-Notifications** — FCM v1 für Android
- **Selbstzerstörende Nachrichten** — TTL (30/90 Tage), Stake-Gate

### DeFi & Trading

- **HTLC Atomic Swaps** — SHA-256 Hash-Lock, 24h Time-Lock, Trustless Trading
- **Token Bridge** — Wrapped Tokens (wUSDT, wBTC, wETH, wUSDC, wTRX)
- **Market Simulator** — Testnet Preis-Simulation (1 STONE = 0.10 TC$)

### Infrastruktur

- **P2P-Netzwerk** — libp2p mit QUIC, TCP, Noise, Gossipsub, Kademlia, mDNS, Relay, UPnP
- **Proof-of-Storage** — Netzwerk-getriebene Challenges, Reputation-Rewards
- **Erasure-Coded Sharding** — Reed-Solomon (k+m) für redundante Chunk-Verteilung
- **Snapshots** — Tar+Zstd komprimiert, automatische Erstellung alle N Blöcke
- **OTA Updates** — Ed25519-signierte Binaries, P2P-Distribution via Gossip

### Game SDK

- **NFT-Marketplace** — Listings, Buy/Sell, Angebote, Preishistorie
- **Game-Wallets** — Separate In-Game Wallets, Spending-Limits, Consent-System
- **Turniere** — Prize-Pools, Leaderboards, Belohnungen
- **Audit-Log** — Vollständige Action-History für Compliance

---

## Schnellstart

### Voraussetzungen

- Rust ≥ 1.75, `cargo` im PATH
- RocksDB-Abhängigkeiten (`libclang`, `llvm` auf macOS: `brew install llvm`)

### Build & Start

```bash
# Release-Build (empfohlen)
cargo build --release

# Testnet starten (Standard)
./start.sh

# Oder direkt:
./target/release/stone-setup
```

Der Setup-Wizard fragt interaktiv nach Node-Name, Passwort und Speicher. Danach startet der Full-Node automatisch.

### Miner starten

```bash
# Miner verbindet sich mit lokaler Node
./target/release/stone-miner
```

Dashboard auf `http://localhost:8080` im Browser.

---

## Netzwerk-Konfiguration

Stone unterstützt parallelen Betrieb von **Mainnet** und **Testnet** auf demselben Server.

### Port-Schema

| | Testnet (Standard) | Mainnet |
|--|---|---|
| **HTTP API** | 3080 | 3180 |
| **P2P (TCP + QUIC)** | 4001 | 5001 |
| **Sync (Node-zu-Node)** | 4002 | 5002 |
| **Datenverzeichnis** | `stone_data/` | `stone_data_mainnet/` |
| **Chain-ID** | `stone-testnet` | `stone-mainnet` |

### Beide Netzwerke starten

```bash
# Terminal 1: Testnet (Default)
STONE_NETWORK=testnet ./target/release/stone-master

# Terminal 2: Mainnet
STONE_NETWORK=mainnet ./target/release/stone-master
```

Die Seed-Nodes, Ports und Datenverzeichnisse werden automatisch nach Netzwerk getrennt. Kein manuelles Port-Mapping nötig.

### Netzwerk-Isolation

- **Getrennte Seed-Nodes** — Testnet-Peers auf Port 4001, Mainnet-Peers auf Port 5001
- **Getrennte Daten** — Separate RocksDB-Instanzen, kein Datenmix
- **Chain-ID Replay-Schutz** — Transaktionen enthalten `chain_id`, Cross-Chain-Replay unmöglich
- **Alle Ports per ENV überschreibbar** — Für individuelle Setups

### Seed-Nodes

| VPS | Testnet | Mainnet |
|-----|---------|---------|
| VPS1 (212.227.54.241) | TCP/UDP 4001 | TCP/UDP 5001 |
| VPS2 (69.48.200.255) | TCP/UDP 4001 | TCP/UDP 5001 |

Seed-Nodes können per `STONE_NO_SEED=1` deaktiviert werden (für private Netzwerke).

---

## Umgebungsvariablen

### Netzwerk

| Variable | Standard | Beschreibung |
|---|---|---|
| `STONE_NETWORK` | `testnet` | Netzwerk: `testnet` oder `mainnet` |
| `STONE_NO_SEED` | `0` | `1` = keine eingebauten Seed-Nodes (isoliertes Netz) |

### Ports

| Variable | Testnet | Mainnet | Beschreibung |
|---|---|---|---|
| `STONE_HTTP_PORT` / `STONE_PORT` | 3080 | 3180 | HTTP/REST API Port |
| `STONE_P2P_PORT` | 4001 | 5001 | libp2p Port (TCP + QUIC) |
| `STONE_SYNC_PORT` | 4002 | 5002 | Sync-API (kein Auth, Node-zu-Node) |
| `STONE_P2P_LISTEN` | — | — | Volle Multiaddr, überschreibt Port |

### Daten & Identität

| Variable | Standard | Beschreibung |
|---|---|---|
| `STONE_DATA_DIR` | `stone_data` / `stone_data_mainnet` | Datenverzeichnis (auto nach Netzwerk) |
| `STONE_NODE_ID` / `STONE_NODE_NAME` | Hostname | Node-Identifikator |
| `STONE_CLUSTER_API_KEY` | — | Admin-API-Key (Priorität 1) |
| `STONE_API_KEY` | — | Fallback Admin-API-Key (Priorität 2) |
| `STONE_PASSWORD` | — | Admin-Passwort (Docker/Setup) |

### P2P Bootstrap

| Variable | Beschreibung |
|---|---|
| `STONE_BOOTSTRAP_NODES` | HTTP-Bootstrap-Nodes (kommagetrennt) |
| `STONE_SEED_PEERS` | libp2p-Multiaddrs (kommagetrennt) |
| `STONE_RELAY_NODES` | Relay-Server für NAT-Traversal |
| `STONE_RELAY_SERVER` | `1` = dieser Node als Relay aktivieren |

### Docker

| Variable | Beschreibung |
|---|---|
| `STONE_DOCKER` | `1` = Docker-Modus (automatisch via Entrypoint) |
| `STONE_STORAGE_GB` | Angebotener Speicher in GB (default: 50) |

---

## Binaries & Tools

| Binary | Beschreibung |
|---|---|
| `stone-setup` | Interaktiver Setup-Wizard → startet danach als Full-Node |
| `stone-master` | Haupt-Node: REST API, WebSocket, PoA, P2P, Mining |
| `stone-miner` | Standalone-Miner mit TUI-Dashboard (CPU/RAM/Disk) |
| `stone-keygen` | Ed25519 Schlüsselpaar-Generator für Validators |
| `stone-publish-update` | OTA-Update veröffentlichen (Ed25519-signiert) |
| `stone-auth` | TLS-Zertifikat-Ausstelldienst für Cluster |
| `db-dump` | RocksDB-Datenbank Inspektion |

---

## API-Übersicht

Alle Endpunkte unter `http://localhost:3080` (Testnet) bzw. `:3180` (Mainnet).

### System & Status

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/health` | Nein | Liveness + Netzwerk + Chain-ID |
| `GET` | `/api/v1/status` | Nein | Vollständiger Node-Status |
| `GET` | `/api/v1/info` | Nein | Node-Info für Peer-Discovery |
| `GET` | `/api/v1/metrics` | Admin | Upload/Download-Zähler, Uptime |
| `GET` | `/api/v1/dashboard` | Admin | Dashboard-Daten |
| `WS` | `/ws` | Nein | Real-Time Events (Blocks, TXs, Peers) |

### Token & Wallet

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `POST` | `/api/v1/token/transfer` | User | Signierte Token-Transaktion |
| `POST` | `/api/v1/token/send` | User | Mnemonic-basierter Transfer |
| `GET` | `/api/v1/token/supply` | Nein | Aktuelles Token-Supply |
| `GET` | `/api/v1/token/pending` | Nein | Pending Mempool Transaktionen |
| `GET` | `/api/v1/token/history/:addr` | Nein | TX-Historie einer Adresse |
| `GET` | `/api/v1/wallet/:addr/balance` | Nein | Wallet-Balance + Nonce |
| `POST` | `/api/v1/wallet/create` | User | Neues Wallet erstellen |

### Staking

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/staking/pool` | Nein | Pool-Info (APY, Total Staked) |
| `GET` | `/api/v1/staking/staker/:addr` | Nein | Staker-Details |

### Mining

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/mining/status` | Admin | Mining-Status |
| `POST` | `/api/v1/mining/template` | Admin | Block-Template anfordern |
| `POST` | `/api/v1/mining/submit` | Admin | Geminten Block einreichen |

### Chat & Organisationen

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `POST` | `/api/v1/chat/send` | User | Nachricht senden (E2E-verschlüsselt) |
| `GET` | `/api/v1/chat/conversations` | User | Alle Konversationen |
| `POST` | `/api/v1/chat/send-coins` | User | Coins im Chat senden |
| `POST` | `/api/v1/orgs` | User | Organisation erstellen |
| `GET` | `/api/v1/orgs` | User | Eigene Organisationen |

### HTLC & Bridge

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `POST` | `/api/v1/htlc/create` | User | Atomic Swap erstellen |
| `POST` | `/api/v1/htlc/claim` | User | Swap einlösen (Preimage) |
| `POST` | `/api/v1/bridge/deposit` | User | Wrapped Token einzahlen |
| `POST` | `/api/v1/bridge/withdraw` | User | Wrapped Token auszahlen |

### Governance & Konsensus

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `POST` | `/api/v1/governance/vote` | User | Governance-Vote abgeben |
| `GET` | `/api/v1/validators` | Admin | Validator-Whitelist |
| `GET` | `/api/v1/consensus/status` | Admin | Konsensus-Runde |

### Game SDK (40+ Endpunkte)

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `POST` | `/api/v1/sdk/register` | User | Spiel registrieren |
| `POST` | `/api/v1/sdk/marketplace/list` | User | NFT listen |
| `POST` | `/api/v1/sdk/marketplace/buy` | User | NFT kaufen |
| `POST` | `/api/v1/sdk/tournament/create` | User | Turnier erstellen |

*Vollständige API-Dokumentation: alle Routen in `src/bin/server/router.rs`*

---

## Authentifizierung

### Admin-Key (x-api-key)

```http
x-api-key: sk_38e597...
```

Gesetzt via `STONE_CLUSTER_API_KEY` oder `STONE_API_KEY`.

### Session-Token (Bearer)

```http
Authorization: Bearer <session_token>
```

Ablauf:
1. `POST /api/v1/auth/challenge` → Server sendet Challenge
2. Client signiert Challenge mit Ed25519 Private Key
3. `POST /api/v1/auth/verify` → Server gibt Session-Token (24h TTL, HMAC-SHA256)

### QR-Code Login (Cross-Device)

1. `POST /api/v1/auth/qr/create` → `{ login_token, expires_in }`
2. App scannt QR, bestätigt via `POST /api/v1/auth/qr/confirm`
3. Browser pollt `GET /api/v1/auth/qr/status/:token` → Session-Token

### BIP-39 Wiederherstellung

12- oder 24-Wort Mnemonic-Phrase → Ed25519-Keypair → Wallet-Adresse. Die Phrase wird beim Signup einmalig ausgegeben.

---

## Docker Deployment

### Beide Netzwerke starten

```bash
docker-compose -f docker/docker-compose.yml up --build
```

### Nur ein Netzwerk

```bash
# Nur Testnet
docker-compose -f docker/docker-compose.yml up --build node-testnet

# Nur Mainnet
docker-compose -f docker/docker-compose.yml up --build node-mainnet
```

### Port-Mapping (Docker)

| Service | HTTP | P2P | Volume |
|---|---|---|---|
| `node-testnet` | 8080 | 4001 | `testnet_data` |
| `node-mainnet` | 8180 | 5001 | `mainnet_data` |

### Systemd (direkt auf VPS)

```bash
sudo cp configs/stone-node.service /etc/systemd/system/
sudo systemctl enable --now stone-node
```

---

## Projektstruktur

```
stone/
├── src/
│   ├── lib.rs                  # Modul-Baum
│   ├── blockchain.rs           # Block-Structs, Chain-Logik, RocksDB
│   ├── consensus.rs            # PoA: Validators, Voting, Fork-Erkennung
│   ├── crypto.rs               # Ed25519, X25519, AES-256-GCM, Argon2id
│   ├── master_node.rs          # MasterNodeState, Upload-Logik, Events
│   ├── network/                # libp2p P2P (Gossipsub, Kademlia, Relay)
│   ├── storage.rs              # Chunk-Store (Content-Addressed)
│   ├── storage_proof.rs        # Proof-of-Storage Challenges
│   ├── chat.rs                 # E2E-verschlüsselter Chat
│   ├── chat_policy.rs          # Self-Destruct, Reporting, Stake-Gate
│   ├── message_pool.rs         # Off-Chain Messages + Merkle-Batch
│   ├── merkle_batch.rs         # Merkle-Tree für Chat-Anchoring
│   ├── organization.rs         # Org-Management (Rollen, Channels)
│   ├── shard.rs                # Erasure-Coding (Reed-Solomon)
│   ├── snapshot.rs             # Zstd-Snapshots für Fast-Sync
│   ├── updater.rs              # OTA-Update (Ed25519-signiert)
│   ├── auth.rs                 # User-Auth, BIP39, QR-Login
│   ├── token/
│   │   ├── mod.rs              # Token-Modul Einstieg
│   │   ├── ledger.rs           # Account-Ledger (RocksDB)
│   │   ├── transaction.rs      # TokenTx, Signatur, Chain-ID
│   │   ├── genesis.rs          # 50M Genesis-Allocation
│   │   ├── wallet.rs           # Ed25519 Wallet, BIP39
│   │   ├── address.rs          # Bech32m (stone1...) Adressen
│   │   ├── mempool.rs          # TX-Queue mit Validierung
│   │   ├── staking.rs          # PoS-Pool, Epochs, Rewards
│   │   ├── governance.rs       # Dual-Vote, Multisig, Timelock
│   │   ├── reputation.rs       # Node-Reputation (0-100)
│   │   ├── bridge.rs           # Wrapped Token Bridge
│   │   ├── htlc.rs             # Hash Time-Locked Contracts
│   │   ├── market_sim.rs       # Testnet Markt-Simulator
│   │   └── game_economy.rs     # Game SDK (NFTs, Marketplace)
│   └── bin/
│       ├── master_server.rs    # Haupt-Binary: REST + WS + P2P
│       ├── stone_miner.rs      # Standalone-Miner mit TUI
│       ├── setup.rs            # Setup-Wizard + Full-Node
│       ├── auth_server.rs      # TLS-Zertifikat-Authority
│       ├── stone_keygen.rs     # Ed25519 Key-Generator
│       ├── stone_publish_update.rs  # OTA-Publish Tool
│       ├── db_dump.rs          # DB-Inspektion
│       └── server/             # Axum Router + Handler (150+ Endpunkte)
├── docker/
│   ├── docker-compose.yml      # Testnet + Mainnet Services
│   ├── Dockerfile              # Multi-Stage Build
│   └── entrypoint.sh           # Auto-Setup + OTA
├── configs/
│   └── stone-node.service      # Systemd Unit
├── scripts/                    # Deploy, Release, Airdrop Tools
├── stone_data/                 # Testnet-Daten (gitignored)
├── stone_data_mainnet/         # Mainnet-Daten (gitignored)
├── start.sh                    # Quick-Start Script
└── Cargo.toml                  # 7 Binaries, 50+ Dependencies
```

---

## Technologie-Stack

| Komponente | Technologie |
|---|---|
| **Runtime** | Tokio (async, multi-threaded) |
| **HTTP** | Axum 0.8 (REST + WebSocket + Multipart) |
| **P2P** | libp2p 0.55 (QUIC, TCP, Gossipsub, Kademlia, mDNS, Relay, UPnP) |
| **Persistenz** | RocksDB 0.22 (Snappy, Column Families) |
| **Kryptographie** | Ed25519-dalek, X25519-dalek, AES-256-GCM, SHA-256, Argon2id |
| **Adressen** | Bech32m (`stone1...`), intern 64-Hex |
| **Serialisierung** | serde_json + bincode |
| **Präzision** | rust_decimal (8 Dezimalstellen) |
| **Erasure Coding** | Reed-Solomon 6.0 |
| **Kompression** | tar + zstd |
| **TUI** | Ratatui (Miner Dashboard) |
| **Setup UI** | Dialoguer + Indicatif |

---

## Curl-Beispiele

```bash
export KEY="sk_38e597..."
export BASE="http://localhost:3080"    # Testnet
# export BASE="http://localhost:3180"  # Mainnet

# Health-Check (zeigt Netzwerk + Chain-ID)
curl "$BASE/api/v1/health"

# Token-Supply
curl "$BASE/api/v1/token/supply"

# Wallet-Balance
curl "$BASE/api/v1/wallet/stone1abc.../balance"

# Token-Transfer (mit Mnemonic)
curl -X POST -H "x-api-key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"mnemonic":"word1 word2 ...","to":"stone1xyz...","amount":"10.0"}' \
  "$BASE/api/v1/token/send"

# Staking-Pool Info
curl "$BASE/api/v1/staking/pool"

# Chat-Nachricht senden
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to":"user-id","content":"Hallo!"}' \
  "$BASE/api/v1/chat/send"

# Alle Validators
curl -H "x-api-key: $KEY" "$BASE/api/v1/validators"
```
