# Stone Blockchain: Data Sharding mit Erasure Coding

## Aktueller Zustand: Full Replication

```
Jede Node speichert ALLES:
  Node A: [Block₀..Blockₙ] + [Chunk₁, Chunk₂, ..., Chunkₘ]   = 100%
  Node B: [Block₀..Blockₙ] + [Chunk₁, Chunk₂, ..., Chunkₘ]   = 100%  ← Kopie
  Node C: [Block₀..Blockₙ] + [Chunk₁, Chunk₂, ..., Chunkₘ]   = 100%  ← Kopie
```

**Problem**: 10 Nodes × 50 GB = 500 GB, aber nur 50 GB einzigartige Daten.

---

## Neues Modell: Erasure-Coded Chunk Distribution

### Grundidee

Wir trennen zwei Ebenen:

| Ebene | Was | Replikation |
|-------|-----|-------------|
| **Blockchain** (Blöcke + Metadaten) | Block-Header, Dokument-Metadaten, Hashes | **Full Replication** – jede Node |
| **Chunk-Storage** (Binärdaten) | Die eigentlichen Datei-Bytes (8 MiB Chunks) | **Erasure-Coded Sharding** |

> Die Blockchain selbst ist klein (nur Metadaten + Hashes). Die **Chunks** sind
> das Speicher-Problem. Deshalb sharden wir nur die Chunks.

### Reed-Solomon Erasure Coding

```
Original-Chunk (8 MiB):  [████████████████████████████████████]
                                      │
                          Reed-Solomon (k=4, m=2)
                                      │
                    ┌─────┬─────┬─────┬─────┬─────┬─────┐
                    │ S₁  │ S₂  │ S₃  │ S₄  │ P₁  │ P₂  │
                    │2MiB │2MiB │2MiB │2MiB │2MiB │2MiB │
                    └──┬──┴──┬──┴──┬──┴──┬──┴──┬──┴──┬──┘
                       │     │     │     │     │     │
                    Node A  Node B Node C Node D Node E Node F

Rekonstruktion: Beliebige 4 von 6 Shards → Original ✓
Platzbedarf pro Node: ~33% statt 100%
Ausfalltoleranz: 2 beliebige Nodes können gleichzeitig ausfallen
```

### Parameter

| Parameter | Wert | Bedeutung |
|-----------|------|-----------|
| `k` (Daten-Shards) | 4 | Minimum Shards für Rekonstruktion |
| `m` (Paritäts-Shards) | 2 | Zusätzliche Redundanz |
| `n = k + m` | 6 | Totale Shards pro Chunk |
| Chunk-Größe | 8 MiB | Bestehende `CHUNK_SIZE` |
| Shard-Größe | 2 MiB | `CHUNK_SIZE / k` |

### Speicher-Ersparnis

| Nodes | Full Replication | Erasure Coding (4,2) | Ersparnis |
|-------|-----------------|---------------------|-----------|
| 6 | 6 × 100% = 600% | 6 × ~17% = 100% + 50% Redundanz | **75%** |
| 10 | 10 × 100% = 1000% | Jede Node: ~17% | **83%** |
| 20 | 20 × 100% = 2000% | Jede Node: ~8.5% | **91.5%** |

---

## Architektur-Änderungen

### 1. Neues `ShardRef` in `blockchain.rs`

```rust
/// Ein Shard ist ein Fragment eines erasure-coded Chunks.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShardRef {
    pub chunk_hash: String,      // Original-Chunk-Hash (für Zuordnung)
    pub shard_index: u8,         // 0..k-1 = Daten, k..k+m-1 = Parität
    pub shard_hash: String,      // SHA-256 des Shard-Inhalts
    pub shard_size: u64,
    pub holder: String,          // PeerId des Nodes der diesen Shard hält
}
```

### 2. `ChunkRef` wird erweitert

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChunkRef {
    pub hash: String,
    pub size: u64,
    // NEU:
    pub shards: Vec<ShardRef>,   // Erasure-coded Shard-Verteilung
    pub ec_k: u8,                // Daten-Shards (z.B. 4)
    pub ec_m: u8,                // Paritäts-Shards (z.B. 2)
}
```

### 3. `ShardStore` (neben `ChunkStore`)

```rust
pub struct ShardStore {
    base_dir: PathBuf,  // stone_data/shards/<chunk_hash>/<shard_index>
}

impl ShardStore {
    /// Speichert die Shards die DIESER Node halten soll
    pub fn store_my_shards(&self, chunk_hash: &str, shards: &[(u8, Vec<u8>)]) -> Result<()>;
    
    /// Liest einen lokalen Shard
    pub fn read_shard(&self, chunk_hash: &str, shard_index: u8) -> Result<Vec<u8>>;
    
    /// Prüft welche Shards lokal vorhanden sind
    pub fn local_shards(&self, chunk_hash: &str) -> Vec<u8>;
    
    /// Rekonstruiert den Original-Chunk aus k Shards
    pub fn reconstruct_chunk(&self, chunk_hash: &str, ec_k: u8) -> Result<Vec<u8>>;
}
```

### 4. Shard-Zuordnung via Kademlia DHT

Die Zuordnung "welcher Node hält welchen Shard" nutzt **Kademlia** (haben wir schon!):

```
Shard-Key = SHA-256(chunk_hash || shard_index)

PUT: kad.put_record(shard_key, holder_peer_id)
GET: kad.get_record(shard_key) → PeerId → P2P-Request → Shard-Daten
```

### 5. Neues P2P-Protokoll: `ShardExchange`

```rust
#[derive(Serialize, Deserialize)]
enum ShardRequest {
    /// Frage: Hast du diesen Shard?
    GetShard { chunk_hash: String, shard_index: u8 },
    /// Antwort: Hier ist der Shard
    ShardData { chunk_hash: String, shard_index: u8, data: Vec<u8> },
    /// Speichere diesen Shard für mich
    StoreShard { chunk_hash: String, shard_index: u8, data: Vec<u8> },
}
```

---

## Ablauf: Dokument hochladen

```
1. Client lädt Datei hoch (z.B. 32 MiB PDF)

2. Server chunked in 8 MiB Blöcke → 4 Chunks

3. Für jeden Chunk:
   a. Reed-Solomon Encoding (k=4, m=2) → 6 Shards à 2 MiB
   b. Shard-Zuordnung:
      - XOR-Distance(shard_key, peer_id) → nächste k+m Peers im DHT
      - Oder: Round-Robin mit Gewichtung nach freiem Speicher
   c. Shards an zugewiesene Peers verteilen (P2P ShardExchange)
   d. ShardRefs im Block-Dokument speichern

4. Block wird normal an alle Nodes repliziert
   (nur Metadaten + ShardRefs, NICHT die Chunk-Daten!)

5. Fertig: Chunk-Daten verteilt, Metadaten überall
```

## Ablauf: Dokument lesen

```
1. Client fragt Dokument an

2. Server liest Block → findet ChunkRef mit ShardRefs

3. Für jeden Chunk:
   a. Prüfe lokale Shards (vielleicht haben wir schon welche)
   b. Falls < k lokale Shards:
      - Kad-DHT lookup: Wo sind die anderen Shards?
      - P2P-Request an Shard-Holder
      - Sammle k Shards (egal welche k von n)
   c. Reed-Solomon Dekodierung → Original-Chunk
   d. Optional: Cache den rekonstruierten Chunk lokal

4. Chunks zusammenfügen → Original-Datei → an Client
```

---

## Implementierungs-Phasen

### Phase 1: Reed-Solomon Library (Cargo.toml)
```toml
reed-solomon-erasure = "6.0"  # Bewährte RS-Library
```

### Phase 2: ShardStore + Encoding/Decoding
- `src/shard.rs` — ShardStore, encode_chunk(), decode_chunk()
- Unit-Tests: Encode → delete 2 Shards → Decode = Original

### Phase 3: P2P ShardExchange Protokoll
- Request-Response für Shard-Transfer
- Kad-DHT Records für Shard-Location
- In `StoneBehaviour` integrieren

### Phase 4: Upload-Flow anpassen
- `write_chunks()` → `write_and_distribute_shards()`
- ShardRefs in ChunkRef speichern
- Verteilung an Peers

### Phase 5: Download-Flow anpassen
- `reconstruct_document()` → Shard-basiert
- Lokale Shards + Remote-Shards sammeln
- Reed-Solomon Dekodierung

### Phase 6: Monitoring + Gesundheits-Checks
- Shard-Health im Node-Monitor anzeigen
- Repair: Wenn ein Node ausfällt → Shards neu verteilen
- `shard_health_score` pro Dokument

---

## Abwärtskompatibilität

Bestehende Chunks (Full Replication) bleiben funktional:
- `ChunkRef.shards` ist leer → Legacy-Modus → `ChunkStore.read_chunk()`
- `ChunkRef.shards` ist gefüllt → Shard-Modus → `ShardStore.reconstruct()`

```rust
pub fn read_document_data(doc: &Document) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    for chunk_ref in &doc.chunks {
        let chunk_data = if chunk_ref.shards.is_empty() {
            // Legacy: Full-Replication Chunk
            chunk_store.read_chunk(&chunk_ref.hash)?
        } else {
            // Neu: Erasure-Coded Shards
            shard_store.reconstruct_chunk(&chunk_ref.hash, chunk_ref.ec_k)?
        };
        data.extend_from_slice(&chunk_data);
    }
    Ok(data)
}
```

---

## Rust-Crates

| Crate | Zweck |
|-------|-------|
| `reed-solomon-erasure` | RS-Encoding/Decoding |
| `libp2p` (haben wir) | Shard-Transfer via P2P |
| `rocksdb` (haben wir) | Shard-Metadaten Index |
| `sha2` (haben wir) | Shard-Hashing |
