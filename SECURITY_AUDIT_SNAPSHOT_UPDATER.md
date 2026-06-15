# Security-Audit: Snapshot & Updater

**Datum:** $(date +%Y-%m-%d)
**Scope:** `src/snapshot.rs`, `src/updater.rs`, `src/bin/server/handlers/snapshot.rs`, `src/bin/server/handlers/updates.rs`, `src/bin/stone_publish_update.rs`
**Build-Status:** ✅ `cargo check --lib --bins` grün
**Test-Status:** ✅ game_economy 23/23, crypto 4/4

---

## Zusammenfassung

| Severity | Snapshot | Updater | Total |
|----------|---------:|--------:|------:|
| KRITISCH | 1 | 3 | **4** |
| MITTEL   | 3 | 4 | **7** |
| NIEDRIG  | 2 | 3 | **5** |

Insgesamt **16 Findings**. Das System ist grundsätzlich gut konzipiert (Ed25519-Signaturen, Hash-Verifikation, atomare Writes, Rollback-Marker), hat aber sicherheitskritische Lücken im **Trust-Modell** und **Konsens-Erzwingung**.

---

## SNAPSHOT — Findings

### 🚨 S1 — KRITISCH: Attestations werden NIE verifiziert

**Datei:** [src/snapshot.rs:667-942](src/snapshot.rs#L667)

`SnapshotMeta.attestations: Vec<SnapshotAttestation>` existiert, `sign_snapshot_attestation()` und `add_attestation_to_latest()` sind implementiert (L1028-1106) — aber **kein Aufrufer prüft die Attestations** in `verified_download_snapshot` oder `download_snapshot_from_peer`.

Damit ist das gesamte Validator-Attestation-Schema **toter Code**: Staker können signieren, niemand verifiziert.

**Angriff:** Bootstrap-Node liefert manipulierten Snapshot ohne Attestations → wird akzeptiert, da Feld optional und nicht geprüft.

**Fix:** In `verified_download_snapshot` nach Schritt 5 (Archiv-Hash):
- Sammle Attestations aus `best_meta.attestations`
- Verifiziere jede Ed25519-Signatur gegen `"snapshot:{height}:{archive_hash}:{state_root}"`
- Lade Validator-Stakes aus lokalem Ledger (oder über Bootstrap-API)
- Erzwinge: Summe(stake der gültigen Attestations) ≥ ⅔ × eligible_stake (≥ Guardian-Level)

---

### ⚠️ S2 — MITTEL: `download_snapshot_from_peer()` ohne Konsens

**Datei:** [src/snapshot.rs:475-621](src/snapshot.rs#L475)

Single-source-of-trust: Lädt Meta + Archiv vom selben Peer und vergleicht nur archive_hash gegen die Meta vom selben Peer. Genesis-Hash ist der einzige externe Anker.

**Status:** `pub`, aber im aktuellen Codebase nicht aufgerufen (nur `verified_download_snapshot` wird genutzt). Trotzdem öffentliche API → kann von externen Tools oder zukünftigem Code reaktiviert werden.

**Fix:** Entweder `pub(crate)` machen oder Doku-Warnung anbringen oder ganz entfernen.

---

### ⚠️ S3 — MITTEL: state_root-Divergenz wird nur geloggt

**Datei:** [src/snapshot.rs:797-815](src/snapshot.rs#L797)

```rust
// Wir akzeptieren den Snapshot trotzdem, die Post-Restore-Verifikation
// (Schritt 7) prüft die interne Konsistenz des heruntergeladenen Snapshots.
eprintln!("[snapshot] ⚠️  State-Root Divergenz ...");
```

Das Argument ist falsch: Post-Restore Schritt 7 vergleicht `local_sr != best_meta.state_root` — und `best_meta` kommt **vom selben Peer**. Es ist also nur eine Selbst-Konsistenz-Prüfung, **keine Konsens-Prüfung**.

**Angriff:** Zwei Bootstrap-Nodes liefern unterschiedliche state_roots. Angreifer kontrolliert einen davon und liefert internen-konsistenten gefälschten Snapshot.

**Fix:** Bei Divergenz nur Snapshots akzeptieren, deren `state_root` mit der absoluten Mehrheit der Konsens-Nodes übereinstimmt; sonst `ConsensusFailure` werfen.

---

### ⚠️ S4 — MITTEL: Chain-DB Column-Families hartcodiert

**Datei:** [src/snapshot.rs:340](src/snapshot.rs#L340)

```rust
DB::open_cf_for_read_only(&opts, db_path, ["default", "blocks", "meta", "index"], false)
```

Wenn ein neues CF in `chain_db` hinzugefügt wird (z.B. `tx_index`, `events`), wird es **stillschweigend nicht in Snapshots aufgenommen** → Datenverlust beim Restore.

**Fix:** CF-Liste aus zentraler Konstante in `blockchain.rs` ziehen, oder `DB::list_cf` zur Laufzeit nutzen.

---

### ℹ️ S5 — NIEDRIG: `STONE_INSECURE_SSL=1` Escape-Hatch

Drei Stellen in snapshot.rs deaktivieren TLS-Validierung über Env-Var. Für HTTP-Bootstrap-URLs aktuell egal, aber falls Bootstrap auf HTTPS migriert wird, ist das eine MITM-Lücke.

**Fix:** Dokumentieren oder produktive Builds (`#[cfg(not(debug_assertions))]`) sollten die Env-Var ignorieren.

---

### ℹ️ S6 — NIEDRIG: `snapshot_dir()` schluckt Fehler

```rust
fs::create_dir_all(&dir).unwrap_or(());
```
Bei Permission-Denied scheitern alle nachfolgenden Operationen mit kryptischen Fehlern. Lieber `.expect()` mit klarer Fehlermeldung, oder `Result` propagieren.

---

## UPDATER — Findings

### 🚨 U1 — KRITISCH: Trusted-Keys via API entfernbar

**Datei:** [src/bin/server/handlers/updates.rs:419-424](src/bin/server/handlers/updates.rs#L419)

```rust
if let Some(ref keys) = payload.remove_trusted_keys {
    for key in keys {
        updater.config.trusted_keys.retain(|k| k != key);
        ...
    }
}
```

Admin kann **alle trusted_keys entfernen UND neue hinzufügen**. Kompromittiertes Admin-Token → Angreifer ersetzt Signing-Key → liefert eigenes signiertes Update → Code-Execution auf allen Nodes.

Das ist die Defense-in-Depth-Lücke schlechthin: Offline-Signing-Key (Hardware-Key, isolierter Build-Server) verliert seine Bedeutung, wenn ein Online-Admin-Token diesen Schutz aushebeln kann.

**Fix (in dieser Reihenfolge der Härte):**
1. **Minimum:** `trusted_keys` nicht via API entfernbar machen, nur additiv. Entfernen nur via Editier-Datei + Node-Restart.
2. **Besser:** API ganz entfernen — trusted_keys ausschließlich aus `trusted_update_keys.txt` + ENV laden.
3. **Optimal:** trusted_keys in einen separaten ENV-gelockten Bereich (z.B. Sealed-Secret via Disk-Hash) verschieben.

---

### 🚨 U2 — KRITISCH: Auto-Install ohne Re-Verifikation

**Datei:** [src/bin/server/handlers/updates.rs:362-396](src/bin/server/handlers/updates.rs#L362)

In `download_missing_chunks`: nach `verify_and_prepare()` → wenn `auto_install=true`, direkt `updater.install()`. 

`verify_and_prepare` prüft nur den **binary_hash gegen das gespeicherte manifest**. Das Manifest selbst wird seit `receive_manifest` **nicht erneut signaturgeprüft**. Wenn das Manifest zwischen Empfang und Install lokal manipuliert wird (Disk-Tampering, Race-Condition mit `publish_update`, Datei-Corruption + Replay), würde das Binary trotzdem installiert.

**Fix:** Vor jedem `install()` Aufruf `verify_signature(&manifest)` erneut aufrufen. Kosten: einmalige Ed25519-Verifikation, vernachlässigbar.

---

### 🚨 U3 — KRITISCH: `handle_update_chunk` öffentlich + ungebremst

**Datei:** [src/bin/server/handlers/updates.rs:64-83](src/bin/server/handlers/updates.rs#L64)

`GET /api/v1/updates/chunk/:index` ist öffentlich, kein Rate-Limit, kein Size-Limit. Jeder kann beliebig oft alle Chunks parallel anfragen.

**Angriff:** Bandwidth-DoS — Angreifer macht `N × M` parallele Requests, jeder zieht 1 MiB. Bei 500 MiB Binary und 100 parallelen Clients = 50 GB Up-Bandwidth.

**Fix:**
1. Rate-Limit (z.B. `tower-governor` 10 req/s/IP).
2. Optional: Chunks nur an known peers (peer-list intersection) ausliefern.
3. Optional: Auth-Token für Peer-Sync.

---

### ⚠️ U4 — MITTEL: `published_at` und `changelog` nicht im signierten Payload

**Datei:** [src/updater.rs:806-825](src/updater.rs#L806)

`canonical_manifest_bytes` enthält **nicht** `published_at` und `changelog`. Angreifer mit Zugriff auf signiertes Manifest kann:
- Timestamp manipulieren (Re-Broadcast als "neues" Update)
- Changelog komplett austauschen (Social-Engineering: User glaubt es sei ein Sicherheits-Patch)

**Angriff:** Geringer, da version+hash gleich bleiben (Idempotenz greift), aber **Changelog-Spoofing** ist real.

**Fix:** `published_at.to_rfc3339()` und `changelog` mit Length-Prefix in `canonical_manifest_bytes` aufnehmen.

---

### ⚠️ U5 — MITTEL: Cross-Field-Validierung fehlt

**Datei:** [src/updater.rs:208-265](src/updater.rs#L208)

Kein Sanity-Check, ob `chunk_hashes.len()` plausibel zu `binary_size` passt:
- Erwartet: `(chunk_hashes.len() - 1) * chunk_size < binary_size <= chunk_hashes.len() * chunk_size`
- Aktuell akzeptiert: Manifest mit 1.000.000 Chunks für 1-Byte-Binary → HashSet-Blow-up, viele HTTP-Requests bevor die Realität auffliegt.

Auch: `chunk_size` wird nicht gegen `UPDATE_CHUNK_SIZE` validiert — abweichende Werte sollten abgelehnt werden.

**Fix:** Bei `receive_manifest` direkt nach Signatur-Check:
```rust
if manifest.chunk_size != UPDATE_CHUNK_SIZE { return Err(...); }
let expected_min = manifest.binary_size.div_ceil(UPDATE_CHUNK_SIZE as u64);
if manifest.chunk_hashes.len() as u64 != expected_min { return Err(...); }
```

---

### ⚠️ U6 — MITTEL: `handle_update_publish` lädt ALLE Chunks in RAM

**Datei:** [src/bin/server/handlers/updates.rs:91-140](src/bin/server/handlers/updates.rs#L91)

Komplettes JSON-Payload mit base64-kodierten Chunks wird via Axum als `Json<PublishPayload>` deserialisiert. Bei 500 MiB Binary = ~667 MiB base64 + 500 MiB decoded RAM-Peak → OOM auf kleinen Nodes.

**Fix:** 
- Entweder `publish` über Multipart streamen
- Oder per Chunk separat hochladen (`POST /publish/manifest` + `POST /publish/chunk/:i`)
- Oder Max-Body-Size pro Request limitieren (z.B. 100 MiB) und mehrteilig hochladen

---

### ⚠️ U7 — MITTEL: `is_newer_version` ignoriert Pre-Release

**Datei:** [src/updater.rs:836-851](src/updater.rs#L836)

```rust
let parts: Vec<&str> = v.trim_start_matches('v').split('.').collect();
```

`"0.3.0-rc1"` und `"0.3.0"` werden als gleich behandelt. Versionsstring `0.3.0-rc1.malicious` ebenso.

**Angriff:** Insider mit Signing-Key (oder geleakter Key) erzeugt Manifest mit version=`"0.3.0"` aber abweichendem `binary_hash` — Node hält es für Update der bereits laufenden v0.3.0.

**Fix:** `semver`-Crate nutzen, oder zumindest pre-release-Suffix explizit ablehnen.

---

### ℹ️ U8 — NIEDRIG: `try_into().unwrap()` Hot-Path

**Datei:** [src/updater.rs:281, 295, 874](src/updater.rs#L281)

Drei `.unwrap()` nach Length-Checks. Korrekt, aber sollte als `.expect("length checked above")` markiert sein für besseren Crash-Diagnose-Output.

---

### ℹ️ U9 — NIEDRIG: Rollback-Schwelle bei normaler Restart-Folge

**Datei:** [src/updater.rs:910-920](src/updater.rs#L910)

`confirm_update_success` wird 120s nach Start aufgerufen. Bei 3 normalen, gewollten Restarts innerhalb von je <120s → Rollback ausgelöst (false-positive).

**Edge-Case:** OK für normale Operations, aber bei Debug-Sessions (`stone start; ctrl-c; stone start; ...`) führt das zu unbeabsichtigtem Rollback.

**Fix:** Timer-Schwelle dokumentieren oder optional reduzieren auf z.B. 30s.

---

### ℹ️ U10 — NIEDRIG: `published_at` als `DateTime<Utc>` ohne Sanity-Bounds

**Datei:** [src/updater.rs:108](src/updater.rs#L108)

Manifest könnte `published_at` weit in der Zukunft (Year 9999) tragen — kein UI-Issue jetzt, aber sollte begrenzt sein.

---

## Behebungs-Priorität (empfohlen)

### Sofort (KRITISCH)
1. **U1**: trusted_keys-API auf rein additiv beschränken oder ganz entfernen
2. **U2**: `verify_signature` vor jedem `install()` aufrufen
3. **U3**: Rate-Limit auf `/updates/chunk/:index`
4. **S1**: Attestation-Verifikation in `verified_download_snapshot` einbauen

### Mittelfristig (MITTEL)
5. **U4**: `published_at` + `changelog` in canonical signing input
6. **U5**: Manifest cross-field sanity check
7. **S3**: state_root-Divergenz erzwingen statt loggen
8. **S4**: CF-Liste dynamisch
9. **U6**: Publish-Endpoint streamen

### Cleanup (NIEDRIG)
10. **S2**: `download_snapshot_from_peer` deprecaten/`pub(crate)`
11. **U7**: semver-Parsing
12. **S5/S6**, **U8-U10**

---

## Was richtig gut ist

- ✅ **Ed25519-Signing** mit Trusted-Key-Mechanismus
- ✅ **SHA-256 pro Chunk** + Gesamt-Binary-Hash
- ✅ **Atomare Writes** (`.tmp` + rename) in Snapshot-Code
- ✅ **Rollback-Marker** mit Attempt-Counter
- ✅ **Streaming-Download** für Snapshots (Memory-bounded)
- ✅ **Max-Size-Guards** gegen Memory-Exhaustion (`MAX_BINARY_SIZE`, archive_size + 10%)
- ✅ **Docker-Pfad** sauber separiert
- ✅ **Bootstrap-Konsens** (Konzept solide, nur Erzwingung schwach)
- ✅ **RocksDB-Checkpoint** statt naive Copy (konsistent, schnell)
- ✅ **Post-Restore State-Root Verifikation**
