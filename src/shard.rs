//! Stone Shard-Modul – Erasure Coding für Chunk-Distribution
//!
//! Verwendet Reed-Solomon Erasure Coding um Chunks in Shards aufzuteilen
//! und auf mehrere Nodes zu verteilen. Jede Node speichert nur einen Teil
//! der Daten, aber das Netzwerk kann die Originaldaten jederzeit rekonstruieren.
//!
//! ## Terminologie
//!
//! | Begriff | Bedeutung |
//! |---------|-----------|
//! | **Chunk** | 8 MiB Block einer Datei (bestehende Einheit) |
//! | **Shard** | Fragment eines erasure-coded Chunks |
//! | **k** | Anzahl Daten-Shards (Minimum für Rekonstruktion) |
//! | **m** | Anzahl Paritäts-Shards (Redundanz) |
//! | **n = k + m** | Totale Shards pro Chunk |
//!
//! ## Beispiel (k=4, m=2)
//!
//! ```text
//! 8 MiB Chunk → [S₀ 2MiB][S₁ 2MiB][S₂ 2MiB][S₃ 2MiB][P₀ 2MiB][P₁ 2MiB]
//!                 │         │         │         │         │         │
//!              Node A    Node B    Node C    Node D    Node E    Node F
//!
//! Rekonstruktion: Beliebige 4 von 6 Shards → Original-Chunk
//! ```

use anyhow::{anyhow, bail, Context, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::blockchain::{data_dir, ShardRef};

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Standard Daten-Shards (Minimum für Rekonstruktion)
pub const DEFAULT_EC_K: u8 = 4;
/// Standard Paritäts-Shards (Redundanz)  
pub const DEFAULT_EC_M: u8 = 2;

/// Shard-Verzeichnis: stone_data/shards/
pub fn shard_dir() -> String {
    format!("{}/shards", data_dir())
}

// ─── Encoding / Decoding ─────────────────────────────────────────────────────

/// Encodes a chunk into k data shards + m parity shards using Reed-Solomon.
///
/// Returns `n = k + m` shards, each of size `ceil(chunk.len() / k)`.
/// The input is padded with zeros if not evenly divisible by k.
pub fn encode_chunk(chunk: &[u8], k: usize, m: usize) -> Result<Vec<Vec<u8>>> {
    if k == 0 || m == 0 {
        bail!("k und m müssen > 0 sein (k={k}, m={m})");
    }
    if chunk.is_empty() {
        bail!("Chunk darf nicht leer sein");
    }

    let rs = ReedSolomon::new(k, m)
        .map_err(|e| anyhow!("Reed-Solomon init fehlgeschlagen: {e}"))?;

    // Shard-Größe: Jeder Shard = ceil(chunk_len / k)
    let shard_size = (chunk.len() + k - 1) / k;

    // Erstelle k Daten-Shards (mit Padding falls nötig)
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
    for i in 0..k {
        let start = i * shard_size;
        let end = std::cmp::min(start + shard_size, chunk.len());
        let mut shard = Vec::with_capacity(shard_size);
        if start < chunk.len() {
            shard.extend_from_slice(&chunk[start..end]);
        }
        // Padding mit Nullen auf shard_size auffüllen
        shard.resize(shard_size, 0);
        shards.push(shard);
    }

    // Erstelle m leere Paritäts-Shards
    for _ in 0..m {
        shards.push(vec![0u8; shard_size]);
    }

    // Reed-Solomon Encoding: Füllt die Paritäts-Shards
    rs.encode(&mut shards)
        .map_err(|e| anyhow!("Reed-Solomon Encoding fehlgeschlagen: {e}"))?;

    Ok(shards)
}

/// Decodes k (or more) shards back into the original chunk.
///
/// `shard_data` maps shard_index → shard bytes. At least k shards must be present.
/// The original chunk size is needed to strip padding.
pub fn decode_chunk(
    shard_data: &HashMap<usize, Vec<u8>>,
    k: usize,
    m: usize,
    original_size: usize,
) -> Result<Vec<u8>> {
    if shard_data.len() < k {
        bail!(
            "Zu wenige Shards: {} vorhanden, {} benötigt",
            shard_data.len(),
            k
        );
    }

    let rs = ReedSolomon::new(k, m)
        .map_err(|e| anyhow!("Reed-Solomon init fehlgeschlagen: {e}"))?;

    let n = k + m;

    // Bestimme Shard-Größe aus vorhandenen Shards
    let shard_size = shard_data
        .values()
        .next()
        .ok_or_else(|| anyhow!("Keine Shards vorhanden"))?
        .len();

    // Baue Shard-Array mit Option<Vec<u8>> (None = fehlender Shard)
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; n];
    for (&idx, data) in shard_data {
        if idx >= n {
            bail!("Ungültiger Shard-Index: {idx} (max {n})");
        }
        if data.len() != shard_size {
            bail!(
                "Shard {idx} hat falsche Größe: {} (erwartet {shard_size})",
                data.len()
            );
        }
        shards[idx] = Some(data.clone());
    }

    // Reed-Solomon Reconstruction
    rs.reconstruct(&mut shards)
        .map_err(|e| anyhow!("Reed-Solomon Dekodierung fehlgeschlagen: {e}"))?;

    // Daten-Shards (0..k) zusammenfügen und auf original_size trimmen
    let mut result = Vec::with_capacity(original_size);
    for shard in shards.iter().take(k) {
        if let Some(data) = shard {
            result.extend_from_slice(data);
        } else {
            bail!("Daten-Shard fehlt nach Rekonstruktion");
        }
    }
    result.truncate(original_size);

    Ok(result)
}

/// Berechnet den SHA-256 Hash eines Shards.
pub fn shard_hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ─── ShardStore ──────────────────────────────────────────────────────────────

/// Lokaler Speicher für Erasure-Coded Shards.
///
/// Layout: `stone_data/shards/<chunk_hash>/<shard_index>`
///
/// Jede Node speichert nur die Shards die ihr zugewiesen wurden.
/// Bei Rekonstruktion werden fehlende Shards von anderen Nodes geholt.
#[derive(Clone)]
pub struct ShardStore {
    base_dir: PathBuf,
}

impl ShardStore {
    /// Erstellt einen neuen ShardStore.
    pub fn new() -> Result<Self> {
        let base_dir = PathBuf::from(shard_dir());
        std::fs::create_dir_all(&base_dir)
            .context("ShardStore-Verzeichnis erstellen")?;
        Ok(Self { base_dir })
    }

    /// Validiert dass ein chunk_hash nur aus Hex-Zeichen besteht.
    /// Verhindert Path-Traversal-Angriffe über manipulierte Hashes (z.B. "../../etc").
    fn validate_chunk_hash(hash: &str) -> Result<()> {
        if hash.is_empty() || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!(
                "Ungültiges chunk_hash-Format: '{}'",
                &hash[..hash.len().min(20)]
            );
        }
        Ok(())
    }

    /// Pfad zu einem Shard (mit Validierung).
    fn shard_path(&self, chunk_hash: &str, shard_index: u8) -> Result<PathBuf> {
        Self::validate_chunk_hash(chunk_hash)?;
        Ok(self.base_dir.join(chunk_hash).join(format!("{shard_index}")))
    }

    /// Speichert einen Shard lokal.
    pub fn write_shard(
        &self,
        chunk_hash: &str,
        shard_index: u8,
        data: &[u8],
    ) -> Result<String> {
        Self::validate_chunk_hash(chunk_hash)?;
        let dir = self.base_dir.join(chunk_hash);
        std::fs::create_dir_all(&dir)?;

        let hash = shard_hash(data);
        let path = self.shard_path(chunk_hash, shard_index)?;
        std::fs::write(&path, data)?;

        Ok(hash)
    }

    /// Speichert mehrere Shards die dieser Node halten soll.
    pub fn write_my_shards(
        &self,
        chunk_hash: &str,
        shards: &[(u8, Vec<u8>)],
    ) -> Result<Vec<ShardRef>> {
        let mut refs = Vec::with_capacity(shards.len());
        for (index, data) in shards {
            let hash = self.write_shard(chunk_hash, *index, data)?;
            refs.push(ShardRef {
                chunk_hash: chunk_hash.to_string(),
                shard_index: *index,
                shard_hash: hash,
                shard_size: data.len() as u64,
                holder: String::new(), // wird vom Caller gesetzt
            });
        }
        Ok(refs)
    }

    /// Liest einen lokalen Shard und verifiziert optional seinen Hash.
    pub fn read_shard(&self, chunk_hash: &str, shard_index: u8) -> Result<Vec<u8>> {
        let path = self.shard_path(chunk_hash, shard_index)?;
        std::fs::read(&path)
            .with_context(|| format!("Shard {chunk_hash}/{shard_index} nicht gefunden"))
    }

    /// Liest einen lokalen Shard und prüft seine Integrität gegen den erwarteten Hash.
    ///
    /// Gibt `Err` zurück wenn die Datei nicht existiert oder der Hash nicht stimmt.
    pub fn read_shard_verified(
        &self,
        chunk_hash: &str,
        shard_index: u8,
        expected_hash: &str,
    ) -> Result<Vec<u8>> {
        let data = self.read_shard(chunk_hash, shard_index)?;
        let actual = shard_hash(&data);
        if actual != expected_hash {
            bail!(
                "Shard {chunk_hash}/{shard_index} Integritätsfehler: \
                 erwartet {expected_hash}, bekommen {actual}"
            );
        }
        Ok(data)
    }

    /// Prüft ob ein bestimmter Shard lokal vorhanden ist.
    pub fn has_shard(&self, chunk_hash: &str, shard_index: u8) -> bool {
        self.shard_path(chunk_hash, shard_index)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Gibt alle lokal vorhandenen Shard-Indices für einen Chunk zurück.
    pub fn local_shard_indices(&self, chunk_hash: &str) -> Vec<u8> {
        if Self::validate_chunk_hash(chunk_hash).is_err() {
            return Vec::new();
        }
        let dir = self.base_dir.join(chunk_hash);
        if !dir.exists() {
            return Vec::new();
        }
        std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .parse::<u8>()
                            .ok()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Rekonstruiert einen Chunk aus lokal verfügbaren Shards.
    ///
    /// Gibt `Err` zurück wenn weniger als k Shards lokal lesbar sind.
    /// In dem Fall müssen fehlende Shards erst von anderen Nodes geholt werden.
    ///
    /// Einzelne korrupte/nicht-lesbare Shards werden übersprungen;
    /// die Rekonstruktion klappt solange mindestens k gültige Shards vorhanden sind.
    pub fn try_reconstruct_local(
        &self,
        chunk_hash: &str,
        k: u8,
        m: u8,
        original_size: usize,
    ) -> Result<Vec<u8>> {
        let indices = self.local_shard_indices(chunk_hash);
        if indices.len() < k as usize {
            bail!(
                "Nur {} von {} benötigten Shards lokal für Chunk {chunk_hash}",
                indices.len(),
                k
            );
        }

        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        let mut read_errors = 0usize;
        for idx in indices.iter().take(k as usize + m as usize) {
            match self.read_shard(chunk_hash, *idx) {
                Ok(data) => {
                    shard_data.insert(*idx as usize, data);
                    if shard_data.len() >= k as usize {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[shard] ⚠ Shard {chunk_hash}/{idx} nicht lesbar, überspringe: {e}"
                    );
                    read_errors += 1;
                }
            }
        }

        if shard_data.len() < k as usize {
            bail!(
                "Nur {} von {} benötigten Shards lesbar für Chunk {chunk_hash} \
                 ({read_errors} Lesefehler)",
                shard_data.len(),
                k
            );
        }

        decode_chunk(&shard_data, k as usize, m as usize, original_size)
    }

    /// Rekonstruiert einen Chunk aus einer Mischung lokaler und remote Shards.
    pub fn reconstruct_with_remote(
        &self,
        chunk_hash: &str,
        remote_shards: &HashMap<u8, Vec<u8>>,
        k: u8,
        m: u8,
        original_size: usize,
    ) -> Result<Vec<u8>> {
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();

        // Erst lokale Shards laden
        for idx in self.local_shard_indices(chunk_hash) {
            if let Ok(data) = self.read_shard(chunk_hash, idx) {
                shard_data.insert(idx as usize, data);
            }
        }

        // Dann remote Shards hinzufügen
        for (idx, data) in remote_shards {
            shard_data.entry(*idx as usize).or_insert_with(|| data.clone());
        }

        if shard_data.len() < k as usize {
            bail!(
                "Nicht genug Shards: {} vorhanden (lokal+remote), {} benötigt",
                shard_data.len(),
                k
            );
        }

        decode_chunk(&shard_data, k as usize, m as usize, original_size)
    }

    /// Gesamte lokale Shard-Statistik.
    pub fn stats(&self) -> ShardStats {
        let mut total_shards = 0u64;
        let mut total_bytes = 0u64;
        let mut chunks_with_shards = 0u64;

        if let Ok(entries) = std::fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    chunks_with_shards += 1;
                    if let Ok(shard_entries) = std::fs::read_dir(entry.path()) {
                        for shard_entry in shard_entries.flatten() {
                            total_shards += 1;
                            total_bytes += shard_entry
                                .metadata()
                                .map(|m| m.len())
                                .unwrap_or(0);
                        }
                    }
                }
            }
        }

        ShardStats {
            total_shards,
            total_bytes,
            chunks_with_shards,
        }
    }

    /// Entfernt alle Shards für einen bestimmten Chunk.
    pub fn remove_chunk_shards(&self, chunk_hash: &str) -> Result<u64> {
        Self::validate_chunk_hash(chunk_hash)?;
        let dir = self.base_dir.join(chunk_hash);
        if !dir.exists() {
            return Ok(0);
        }
        let mut freed = 0u64;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                freed += entry.metadata().map(|m| m.len()).unwrap_or(0);
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(&dir);
        Ok(freed)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ShardStats {
    pub total_shards: u64,
    pub total_bytes: u64,
    pub chunks_with_shards: u64,
}

// ─── Shard-Zuordnung ─────────────────────────────────────────────────────────

/// Weist Shards an Peers zu basierend auf XOR-Distance.
///
/// Verwendet Kademlia-ähnliche Distanz: Die n Peers mit der kleinsten
/// XOR-Distanz zum Shard-Key bekommen jeweils einen Shard.
pub fn assign_shards_to_peers(
    chunk_hash: &str,
    peer_ids: &[String],
    k: u8,
    m: u8,
) -> Vec<(u8, String)> {
    let n = (k + m) as usize;

    if peer_ids.is_empty() {
        // Kein Peer verfügbar → alle lokal
        return (0..n as u8).map(|i| (i, String::new())).collect();
    }

    // Für jeden Shard-Index: Berechne Shard-Key und finde nächsten Peer
    // per XOR-Distanz (Kademlia-ähnlich) auf den ersten 8 Bytes.
    let mut assignments = Vec::with_capacity(n);
    for shard_idx in 0..n {
        let shard_key = format!("{chunk_hash}:{shard_idx}");
        let shard_key_hash = Sha256::digest(shard_key.as_bytes());

        // XOR-Distance: Vergleiche die ersten 8 Bytes von Shard-Key-Hash
        // und Peer-Id-Hash. Der Peer mit der kleinsten Distanz bekommt den Shard.
        let shard_prefix = u64::from_be_bytes(
            shard_key_hash[..8].try_into().unwrap_or([0u8; 8]),
        );

        let best_peer_idx = peer_ids
            .iter()
            .enumerate()
            .map(|(i, pid)| {
                let peer_hash = Sha256::digest(pid.as_bytes());
                let peer_prefix = u64::from_be_bytes(
                    peer_hash[..8].try_into().unwrap_or([0u8; 8]),
                );
                (i, shard_prefix ^ peer_prefix)
            })
            .min_by_key(|&(_, dist)| dist)
            .map(|(i, _)| i)
            .unwrap_or(shard_idx % peer_ids.len());

        assignments.push((shard_idx as u8, peer_ids[best_peer_idx].clone()));
    }

    assignments
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = b"Hello Stone Erasure Coding! Dies ist ein Test mit ausreichend Daten fuer k=4 Shards. Wir muessen sicherstellen dass genug Bytes vorhanden sind. ABCDEFGHIJKLMNOP";
        let k = 4;
        let m = 2;

        // Encode
        let shards = encode_chunk(original, k, m).unwrap();
        assert_eq!(shards.len(), k + m);

        // Alle Shards müssen gleich groß sein
        let shard_size = shards[0].len();
        for s in &shards {
            assert_eq!(s.len(), shard_size);
        }

        // Decode mit allen Shards
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_data.insert(i, s.clone());
        }
        let decoded = decode_chunk(&shard_data, k, m, original.len()).unwrap();
        assert_eq!(decoded, original.as_ref());
    }

    #[test]
    fn test_decode_with_missing_shards() {
        let original = b"Test data for erasure coding with missing shards. This needs to be long enough for 4 data shards minimum. ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop";
        let k = 4;
        let m = 2;

        let shards = encode_chunk(original, k, m).unwrap();

        // Lösche 2 Shards (maximale Toleranz bei m=2)
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        // Behalte nur Shard 0, 2, 3, 5 (Shards 1 und 4 "verloren")
        shard_data.insert(0, shards[0].clone());
        shard_data.insert(2, shards[2].clone());
        shard_data.insert(3, shards[3].clone());
        shard_data.insert(5, shards[5].clone());

        let decoded = decode_chunk(&shard_data, k, m, original.len()).unwrap();
        assert_eq!(decoded, original.as_ref());
    }

    #[test]
    fn test_decode_fails_with_too_few_shards() {
        let original = b"Short test data for failure case testing purpose minimum bytes needed.";
        let k = 4;
        let m = 2;

        let shards = encode_chunk(original, k, m).unwrap();

        // Nur 3 Shards (braucht 4) → muss fehlschlagen
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        shard_data.insert(0, shards[0].clone());
        shard_data.insert(1, shards[1].clone());
        shard_data.insert(2, shards[2].clone());

        let result = decode_chunk(&shard_data, k, m, original.len());
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_large_chunk() {
        // Simuliere einen 8 MiB Chunk
        let original: Vec<u8> = (0..8 * 1024 * 1024)
            .map(|i| (i % 256) as u8)
            .collect();
        let k = 4;
        let m = 2;

        let shards = encode_chunk(&original, k, m).unwrap();
        assert_eq!(shards.len(), 6);

        // Jeder Shard sollte ~2 MiB sein
        let expected_shard_size = (original.len() + k - 1) / k;
        for s in &shards {
            assert_eq!(s.len(), expected_shard_size);
        }

        // Reconstruct
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        for (i, s) in shards.iter().enumerate().take(k) {
            shard_data.insert(i, s.clone());
        }
        let decoded = decode_chunk(&shard_data, k, m, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_shard_hash_deterministic() {
        let data = b"deterministic hash test";
        let h1 = shard_hash(data);
        let h2 = shard_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_assign_shards_round_robin() {
        let peers = vec![
            "PeerA".to_string(),
            "PeerB".to_string(),
            "PeerC".to_string(),
        ];
        let assignments = assign_shards_to_peers("test_chunk_hash", &peers, 4, 2);
        assert_eq!(assignments.len(), 6);
        // Alle Shard-Indices müssen 0..5 sein
        for (i, (idx, _)) in assignments.iter().enumerate() {
            assert_eq!(*idx, i as u8);
        }
        // Jeder Peer sollte mindestens 1 Shard bekommen
        let unique_peers: std::collections::HashSet<&str> =
            assignments.iter().map(|(_, p)| p.as_str()).collect();
        assert!(unique_peers.len() <= peers.len());
    }

    #[test]
    fn test_shard_store_roundtrip() {
        // Verwendet temporäres Verzeichnis
        let store = ShardStore {
            base_dir: std::env::temp_dir().join("stone_shard_test"),
        };
        let _ = std::fs::remove_dir_all(&store.base_dir);
        std::fs::create_dir_all(&store.base_dir).unwrap();

        let chunk_hash = "abc123def456";
        let shard_data = vec![
            (0u8, vec![1u8, 2, 3, 4]),
            (1, vec![5, 6, 7, 8]),
            (2, vec![9, 10, 11, 12]),
        ];

        // Schreiben
        let refs = store.write_my_shards(chunk_hash, &shard_data).unwrap();
        assert_eq!(refs.len(), 3);

        // Lesen
        let read_back = store.read_shard(chunk_hash, 0).unwrap();
        assert_eq!(read_back, vec![1, 2, 3, 4]);

        // Existenz-Check
        assert!(store.has_shard(chunk_hash, 0));
        assert!(store.has_shard(chunk_hash, 1));
        assert!(!store.has_shard(chunk_hash, 5));

        // Indices
        let mut indices = store.local_shard_indices(chunk_hash);
        indices.sort();
        assert_eq!(indices, vec![0, 1, 2]);

        // Stats
        let stats = store.stats();
        assert_eq!(stats.total_shards, 3);
        assert_eq!(stats.chunks_with_shards, 1);

        // Aufräumen
        let freed = store.remove_chunk_shards(chunk_hash).unwrap();
        assert!(freed > 0);
        assert!(!store.has_shard(chunk_hash, 0));

        let _ = std::fs::remove_dir_all(&store.base_dir);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shard-Holder-Registry — Out-of-Band Tracking welcher Peer welchen Shard hält
// ═══════════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};
use std::sync::RwLock;

/// Eintrag: Welche Peers halten einen bestimmten Shard?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardHolder {
    pub chunk_hash: String,
    pub shard_index: u8,
    pub holders: Vec<String>,  // PeerIds
    pub last_verified: i64,    // Unix-Timestamp der letzten Prüfung
}

/// Registry aller bekannten Shard-Holder im Netzwerk.
///
/// Diese Datenstruktur ist die **Source-of-Truth** für Shard-Verfügbarkeit,
/// nicht die Blockchain-Metadaten (die nur den initialen Holder enthalten).
///
/// Die Registry wird gefüttert durch:
/// 1. Lokale Uploads (alle Shards lokal + distribute_shards Ergebnis)
/// 2. P2P ShardStored Events (Bestätigung dass ein Peer den Shard hat)
/// 3. P2P ShardReceived Events (eingehende Shards)
/// 4. Periodische ListShards-Abfragen bei Peers
/// 5. Gossipsub Shard-Announcements
pub struct ShardHolderRegistry {
    /// chunk_hash → shard_index → Vec<PeerId>
    entries: RwLock<HashMap<String, HashMap<u8, Vec<String>>>>,
    /// Persistenz-Datei
    persist_path: String,
}

impl ShardHolderRegistry {
    pub fn new() -> Self {
        let path = format!("{}/shard_holders.json", data_dir());
        let entries = if let Ok(data) = std::fs::read_to_string(&path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self {
            entries: RwLock::new(entries),
            persist_path: path,
        }
    }

    /// Registriert einen Holder für einen bestimmten Shard.
    pub fn add_holder(&self, chunk_hash: &str, shard_index: u8, peer_id: &str) {
        let mut map = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let chunk_entry = map.entry(chunk_hash.to_string()).or_default();
        let holders = chunk_entry.entry(shard_index).or_default();
        if !holders.contains(&peer_id.to_string()) {
            holders.push(peer_id.to_string());
        }
    }

    /// Registriert alle Shards als lokal gehalten (nach EC-Encoding).
    pub fn register_local_shards(&self, chunk_hash: &str, shard_count: u8, local_peer_id: &str) {
        for i in 0..shard_count {
            self.add_holder(chunk_hash, i, local_peer_id);
        }
    }

    /// Gibt alle Holder für einen bestimmten Shard zurück.
    pub fn holders_for(&self, chunk_hash: &str, shard_index: u8) -> Vec<String> {
        let map = self.entries.read().unwrap_or_else(|e| e.into_inner());
        map.get(chunk_hash)
            .and_then(|m| m.get(&shard_index))
            .cloned()
            .unwrap_or_default()
    }

    /// Gibt die Anzahl der bekannten Holder für einen Chunk zurück (über alle Shards).
    /// Returned: Anzahl Shards mit mindestens einem Holder.
    pub fn available_shards_for_chunk(&self, chunk_hash: &str) -> usize {
        let map = self.entries.read().unwrap_or_else(|e| e.into_inner());
        map.get(chunk_hash)
            .map(|m| m.values().filter(|h| !h.is_empty()).count())
            .unwrap_or(0)
    }

    /// Gibt alle Chunk-Hashes zurück die in der Registry sind.
    pub fn all_chunks(&self) -> Vec<String> {
        self.entries.read().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect()
    }

    /// Entfernt einen Holder von allen seinen Shards (z.B. wenn Peer offline geht).
    pub fn remove_holder(&self, peer_id: &str) {
        let mut map = self.entries.write().unwrap_or_else(|e| e.into_inner());
        for chunk_map in map.values_mut() {
            for holders in chunk_map.values_mut() {
                holders.retain(|h| h != peer_id);
            }
        }
    }

    /// Setzt die Holder-Liste für einen bestimmten Chunk+Shard komplett neu
    /// (z.B. nach einem ListShards-Scan).
    pub fn set_holders(&self, chunk_hash: &str, shard_index: u8, holders: Vec<String>) {
        let mut map = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let chunk_entry = map.entry(chunk_hash.to_string()).or_default();
        chunk_entry.insert(shard_index, holders);
    }

    /// Berechnet den Gesundheitsstatus eines Chunks.
    /// Returns: (status, holder_count) wobei status = "healthy"|"degraded"|"critical"
    pub fn chunk_health(&self, chunk_hash: &str, ec_k: u8) -> (&'static str, usize) {
        let available = self.available_shards_for_chunk(chunk_hash);
        let k = ec_k as usize;
        if available >= k + 1 {
            ("healthy", available)  // Mindestens k+1 Shards = gesund (1 Redundanz)
        } else if available >= k {
            ("degraded", available) // Genau k Shards = noch rekonstruierbar, aber keine Redundanz
        } else {
            ("critical", available) // Weniger als k = Datenverlust möglich
        }
    }

    /// Persistiert die Registry auf Disk.
    pub fn persist(&self) {
        let map = self.entries.read().unwrap_or_else(|e| e.into_inner());
        if let Ok(json) = serde_json::to_string_pretty(&*map) {
            let _ = std::fs::write(&self.persist_path, json);
        }
    }

    /// Entfernt Einträge für Chunks die nicht mehr in der Chain referenziert werden.
    /// Gibt die Anzahl der entfernten Chunk-Einträge zurück.
    pub fn gc(&self, referenced_chunks: &std::collections::HashSet<String>) -> usize {
        let mut map = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|chunk_hash, _| referenced_chunks.contains(chunk_hash));
        before - map.len()
    }

    /// Exportiert die Registry als flache Liste (für Gossipsub-Broadcast).
    pub fn export_flat(&self) -> Vec<ShardHolder> {
        let map = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();
        let mut out = Vec::new();
        for (chunk_hash, shard_map) in map.iter() {
            for (shard_index, holders) in shard_map {
                if !holders.is_empty() {
                    out.push(ShardHolder {
                        chunk_hash: chunk_hash.clone(),
                        shard_index: *shard_index,
                        holders: holders.clone(),
                        last_verified: now,
                    });
                }
            }
        }
        out
    }

    /// Importiert Holder-Daten von einem Peer (merge, nicht überschreiben).
    pub fn merge_from_peer(&self, entries: &[ShardHolder]) {
        for entry in entries {
            for holder in &entry.holders {
                self.add_holder(&entry.chunk_hash, entry.shard_index, holder);
            }
        }
    }

    /// Berechnet Shard-Migrationen die nötig sind um die Verteilung auszugleichen.
    ///
    /// Strategie:
    /// - Für jeden Chunk: Prüfe ob der neue Peer (`new_peer`) laut `assign_shards_to_peers`
    ///   einen Shard halten sollte, ihn aber noch nicht hat.
    /// - Gibt eine Liste von (chunk_hash, shard_index, source_peer, target_peer) zurück.
    ///
    /// `connected_peers` muss die vollständige Liste ALLER verbundenen Peers enthalten
    /// (inkl. dem neuen).
    pub fn compute_rebalance(
        &self,
        connected_peers: &[String],
        local_peer_id: &str,
    ) -> Vec<RebalanceAction> {
        if connected_peers.is_empty() {
            return Vec::new();
        }

        let map = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let mut actions = Vec::new();

        for (chunk_hash, shard_map) in map.iter() {
            // Bestimme n = Anzahl tatsächlich registrierter Shard-Slots.
            // ACHTUNG: Wir verwenden die Anzahl der Einträge in der Map,
            // nicht max(index)+1 — sonst fehlen bei lückenhaften Registries Slots.
            let registered_count = shard_map.len() as u8;
            if registered_count < 2 { continue; }

            // Berechne ideale Zuweisung mit aktuellem Peer-Set
            // n = registered_count wird als k+m übergeben (k=n, m=0),
            // damit genau n Shard-Zuweisungen berechnet werden.
            let ideal = assign_shards_to_peers(
                chunk_hash,
                connected_peers,
                registered_count, // k+m als total
                0,                // m=0 da registered_count schon k+m repräsentiert
            );

            for (shard_idx, ideal_peer) in &ideal {
                if ideal_peer.is_empty() { continue; }

                let current_holders = shard_map
                    .get(shard_idx)
                    .cloned()
                    .unwrap_or_default();

                // Soll-Peer hat den Shard schon? → nichts zu tun
                if current_holders.contains(ideal_peer) {
                    continue;
                }

                // Finde einen Source-Peer der den Shard hat
                let source = current_holders.iter()
                    .find(|h| connected_peers.contains(h) || *h == local_peer_id)
                    .cloned()
                    .unwrap_or_else(|| local_peer_id.to_string());

                actions.push(RebalanceAction {
                    chunk_hash: chunk_hash.clone(),
                    shard_index: *shard_idx,
                    source_peer: source,
                    target_peer: ideal_peer.clone(),
                });
            }
        }

        actions
    }
}

/// Beschreibt eine einzelne Shard-Migration.
#[derive(Debug, Clone)]
pub struct RebalanceAction {
    pub chunk_hash: String,
    pub shard_index: u8,
    pub source_peer: String,
    pub target_peer: String,
}
