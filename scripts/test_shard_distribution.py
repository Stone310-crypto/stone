#!/usr/bin/env python3
"""
Shard Distribution Tester für StoneChain

Lädt ein Test-Dokument hoch und prüft:
- Wie viele Chunks wurden erstellt?
- Wie viele Shards pro Chunk (k + m)?
- Auf wie vielen Nodes sind die Daten verteilt?
- Wie viel Speicher wird gespart (EC ratio)?

Verwendung:
    python3 scripts/test_shard_distribution.py [--file TEST_FILE] [--nodes NODE1,NODE2,...]
"""

import requests
import json
import sys
import os
import hashlib
from pathlib import Path

# ── Konfiguration ─────────────────────────────────────────────────────────────

DEFAULT_NODES = ["http://127.0.0.1:3080", "http://212.227.54.241:3080"]
API_KEY = "stone-local-dev"
TEST_FILE = None  # wird automatisch generiert

def short(s, n=12):
    return s[:n] + "…" + s[-4:] if len(s) > n + 4 else s

def check_node(url):
    """Prüft ob eine Node erreichbar ist."""
    try:
        r = requests.get(f"{url}/api/v1/health", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {
                "online": True,
                "node_id": data.get("node_id", "?"),
                "block_height": data.get("block_height", 0),
                "network": data.get("network", "?"),
            }
    except Exception as e:
        return {"online": False, "error": str(e)}

def upload_file(url, api_key, file_path):
    """Lädt eine Datei per multipart POST auf die Node."""
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        headers = {"x-api-key": api_key}
        try:
            r = requests.post(f"{url}/api/v1/documents", files=files, headers=headers, timeout=120)
            if r.status_code == 201:
                return r.json()
            else:
                return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"error": str(e)}

def get_document_info(url, doc_id):
    """Holt Metadaten eines Dokuments."""
    try:
        r = requests.get(f"{url}/api/v1/documents/{doc_id}", timeout=10)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_node_status(url):
    """Holt den Status einer Node (inkl. Shard-Info)."""
    try:
        r = requests.get(f"{url}/api/v1/status", timeout=10)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def generate_test_file(path, size_mb=2):
    """Erstellt eine Testdatei mit zufälligen Bytes (nicht komprimierbar)."""
    size = size_mb * 1024 * 1024
    with open(path, "wb") as f:
        # Schreibe 64KB Blocks — schneller als einzelne Bytes
        block = os.urandom(65536)
        written = 0
        while written < size:
            chunk = block[:min(65536, size - written)]
            f.write(chunk)
            written += len(chunk)
    print(f"  📁 Testdatei erstellt: {path} ({size_mb} MB)")
    return path

def main():
    print("=" * 64)
    print("  🔬 StoneChain Shard Distribution Tester")
    print("=" * 64)
    print()

    nodes = DEFAULT_NODES
    if len(sys.argv) > 2:
        nodes = sys.argv[2].split(",")

    # ── 1. Nodes prüfen ──────────────────────────────────────────────────
    print("1️⃣  Nodes prüfen…")
    print()
    online_nodes = []
    for url in nodes:
        info = check_node(url)
        status = "✅ ONLINE" if info["online"] else "❌ OFFLINE"
        if info["online"]:
            online_nodes.append(url)
            print(f"  {status}  {url}")
            print(f"           Node: {info['node_id']} | Block: #{info['block_height']} | Netz: {info['network']}")
        else:
            print(f"  {status}  {url} — {info.get('error', 'unbekannt')}")
    print()

    if not online_nodes:
        print("❌ Keine Nodes erreichbar — Abbruch.")
        sys.exit(1)

    # ── 2. Testdatei vorbereiten ─────────────────────────────────────────
    test_file = TEST_FILE
    if test_file is None:
        test_file = "scripts/test_upload_binary.bin"
    if not os.path.exists(test_file):
        test_file = generate_test_file(test_file, 1)

    file_size = os.path.getsize(test_file)
    file_hash = hashlib.sha256()
    with open(test_file, "rb") as f:
        while chunk := f.read(65536):
            file_hash.update(chunk)
    file_sha256 = file_hash.hexdigest()
    print(f"2️⃣  Testdatei: {os.path.basename(test_file)} ({file_size / 1024:.1f} KB)")
    print(f"   SHA-256: {short(file_sha256, 16)}")
    print()

    # ── 3. Upload ────────────────────────────────────────────────────────
    print(f"3️⃣  Upload an {online_nodes[0]}…")
    result = upload_file(online_nodes[0], API_KEY, test_file)
    if "error" in result:
        print(f"   ❌ Upload fehlgeschlagen: {result['error']}")
        sys.exit(1)
    doc_id = result.get("doc_id", "?")
    in_pool = result.get("pool", False)
    print(f"   ✅ Upload erfolgreich")
    print(f"   Doc-ID: {doc_id}")
    print(f"   Im Pool: {'Ja (noch nicht on-chain)' if in_pool else 'Nein (on-chain)'}")
    if result.get("block_index"):
        print(f"   Block: #{result['block_index']}")
    print()

    # ── 4. Dokument-Metadaten analysieren ─────────────────────────────────
    print("4️⃣  Dokument-Metadaten analysieren…")
    doc_info = get_document_info(online_nodes[0], doc_id)
    if "error" in doc_info:
        print(f"   ⚠️ Metadaten nicht abrufbar: {doc_info['error']}")
        print("   (Dokument evtl. noch im Pool — Shard-Info erst on-chain verfügbar)")
    else:
        doc = doc_info.get("document", {})
        chunks_count = doc.get("chunks_count", 0)
        size = doc.get("size", 0)
        print(f"   Titel: {doc.get('title', '?')}")
        print(f"   Größe: {size / 1024:.1f} KB")
        print(f"   Chunks: {chunks_count}")
        print()

    # ── 5. Node-Status abfragen (Shard-Verteilung) ────────────────────────
    print("5️⃣  Shard-Verteilung prüfen…")
    print()
    total_shards = 0
    distributed_nodes = 0
    for url in online_nodes:
        status = get_node_status(url)
        if "error" in status:
            print(f"   ❌ {url} — Fehler: {status['error']}")
            continue

        # Chain-Info
        chain = status.get("chain", {})
        # EC-Info
        ec_info = status.get("blockchain", {}).get("ec", {})
        ec_docs = ec_info.get("ec_documents", 0)
        ec_chunks = ec_info.get("ec_chunks", 0)
        shards_tracked = ec_info.get("shards_tracked", 0)
        shards_local = ec_info.get("shards_local", 0)

        docs_total = chain.get("total_documents", 0)
        node_id = status.get("node_id", "?")
        block_height = chain.get("block_height", 0)

        print(f"   📡 {node_id} ({url})")
        print(f"      Block: #{block_height} | Docs: {docs_total}")
        print(f"      EC-Dokumente: {ec_docs} | EC-Chunks: {ec_chunks}")
        print(f"      Shards gesamt: {shards_tracked} | lokal: {shards_local}")
        if shards_tracked > 0:
            total_shards = max(total_shards, shards_tracked)
            distributed_nodes += 1 if shards_local > 0 else 0
        print()

    # ── 6. Zusammenfassung ───────────────────────────────────────────────
    print("=" * 64)
    print("  📊 Zusammenfassung")
    print("=" * 64)
    print()
    print(f"  Nodes online:       {len(online_nodes)}")
    print(f"  Nodes mit Shards:   {distributed_nodes}")
    print(f"  Test-Doc-ID:        {doc_id}")
    print(f"  Dateigröße:         {file_size / 1024:.1f} KB")
    print(f"  Im Pool:            {'Ja' if in_pool else 'Nein'}")
    print()

    if distributed_nodes >= 2:
        print("  ✅ Shard-Verteilung funktioniert!")
        print(f"  📦 Daten sind auf {distributed_nodes} Nodes verteilt.")
        if distributed_nodes == len(online_nodes):
            print("  🎯 Alle Nodes haben Shards erhalten.")
        else:
            print(f"  ℹ️ {len(online_nodes) - distributed_nodes} Node(s) haben keine Shards.")
    elif distributed_nodes == 1 and len(online_nodes) == 1:
        print("  ℹ️ Nur eine Node online — keine Verteilung möglich.")
        print("  💡 Starte weitere Nodes und wiederhole den Test.")
    else:
        print("  ⚠️ Shard-Verteilung nicht bestätigt.")
        print("  💡 Prüfe die Node-Logs auf [sharding] Einträge.")
    print()

    # ── 7. Speicher-Vergleich ─────────────────────────────────────────────
    print("  💾 Speicher-Analyse")
    print("  " + "-" * 40)
    original_size = file_size
    chunk_count = 1  # minimum
    ec_k, ec_m = 4, 2  # default Reed-Solomon params
    total_shard_data = original_size * (ec_k + ec_m) / ec_k  # worst-case: all shards on all nodes
    saving_pct = (1 - (1.0 / distributed_nodes)) * 100 if distributed_nodes > 0 else 0
    print(f"  Original-Datei:     {original_size / 1024:.1f} KB")
    print(f"  Erasure Coding:     k={ec_k}, m={ec_m} ({(ec_k + ec_m) / ec_k:.1f}x overhead)")
    print(f"  Bei {distributed_nodes} Nodes: ~{original_size / 1024 / distributed_nodes:.1f} KB pro Node")
    print(f"  Speicherersparnis:  ~{saving_pct:.0f}% vs. Full-Replikation")
    print()

    print("  ✅ Test abgeschlossen.")


if __name__ == "__main__":
    main()