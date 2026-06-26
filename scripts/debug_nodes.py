#!/usr/bin/env python3
"""
Stone Node Connectivity Debugger
─────────────────────────────────
Prüft alle Nodes auf:
  - Erreichbarkeit (HTTP + Sync-Port)
  - Block-Höhe, Chain-Hash, Genesis-Hash
  - Peer-Liste & Verbindungsstatus
  - DB-Metadaten (Tabellen-Zähler)
  - Sync-Status & Divergenzen

Kein Tailscale nötig — direkte HTTP-Calls auf die Sync-Ports.

Usage:
  python3 scripts/debug_nodes.py                    # Alle Nodes aus nodes.toml + localhost
  python3 scripts/debug_nodes.py --network mainnet  # Mainnet-Ports
  python3 scripts/debug_nodes.py --quick             # Nur Block-Höhen (schnell)
  python3 scripts/debug_nodes.py --node 212.227.54.241  # Einzelne Node
"""

import sys
import json
import time
import urllib.request
import urllib.error
import ssl
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Konfiguration ───────────────────────────────────────────────────────────

# Nodes aus nodes.toml (Name → IP)
NODES_TOML = {
    "server1":           "100.90.28.68",
    "VPSServer-testnet": "212.227.54.241",
    "VPS2-testnet":      "69.48.200.255",
}

# Lokale Node
LOCAL_NODE = "127.0.0.1"

# Ports pro Network
PORTS = {
    "testnet":  {"http": 3080, "sync": 4002},
    "mainnet":  {"http": 3180, "sync": 5002},
}

# Timeout pro Request
TIMEOUT_SECS = 8

# ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

def http_get(url: str, timeout: int = TIMEOUT_SECS) -> dict | None:
    """Führt einen HTTP-GET aus und gibt das JSON-Ergebnis zurück."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "stone-debug/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {"_error": f"Netzwerkfehler: {e.reason}"}
    except Exception as e:
        return {"_error": str(e)}


def check_node(ip: str, name: str, network: str, quick: bool = False) -> dict:
    """Prüft eine einzelne Node auf allen relevanten Endpoints."""
    ports = PORTS[network]
    sync_url = f"http://{ip}:{ports['sync']}"
    http_url = f"http://{ip}:{ports['http']}"

    result = {
        "name": name,
        "ip": ip,
        "sync_url": sync_url,
        "http_url": http_url,
        "reachable": False,
        "source": None,  # "sync" oder "http"
        "health": None,
        "chain_info": None,
        "peers": None,
        "db_metadata": None,
        "info": None,
    }

    # 1. Health-Check (Sync-Port bevorzugt)
    health = http_get(f"{sync_url}/health")
    if health and "_error" not in health:
        result["reachable"] = True
        result["source"] = "sync"
        result["health"] = health

    if not result["reachable"]:
        # Fallback: HTTP-Port
        health2 = http_get(f"{http_url}/api/v1/health")
        if health2 and "_error" not in health2:
            result["reachable"] = True
            result["source"] = "http"
            result["health"] = health2

    if not result["reachable"]:
        return result

    base_url = sync_url if result["source"] == "sync" else http_url

    # 2. Chain-Info (nur auf Sync-Port)
    if result["source"] == "sync":
        ci = http_get(f"{sync_url}/chain-info")
        if ci and "_error" not in ci:
            result["chain_info"] = ci

    if quick:
        return result

    # 3. Peers (Sync-Port)
    if result["source"] == "sync":
        peers = http_get(f"{sync_url}/peers")
        if peers and "_error" not in peers:
            result["peers"] = peers

    # 4. DB-Metadaten (Sync-Port)
    if result["source"] == "sync":
        dbm = http_get(f"{sync_url}/db-metadata")
        if dbm and "_error" not in dbm:
            result["db_metadata"] = dbm

    # 5. Info (Sync-Port)
    if result["source"] == "sync":
        info = http_get(f"{sync_url}/info")
        if info and "_error" not in info:
            result["info"] = info

    return result


# ─── Analyse ──────────────────────────────────────────────────────────────────

def analyze(results: list[dict], network: str):
    """Analysiert die Ergebnisse und zeigt Divergenzen."""
    print()
    print("═" * 70)
    print("  📊 ANALYSE")
    print("═" * 70)

    # ── Erreichbarkeit ──────────────────────────────────────────────────
    reachable = [r for r in results if r["reachable"]]
    unreachable = [r for r in results if not r["reachable"]]

    print(f"\n  Erreichbar:   {len(reachable)}/{len(results)}")
    for r in reachable:
        h = r.get("health", {}) or {}
        print(f"    ✅ {r['name']:25s} ({r['ip']:18s})  height={h.get('block_height','?')}  via={r.get('source','?')}")
    for r in unreachable:
        err = (r.get("health") or {}).get("_error", "Keine Antwort")
        print(f"    ❌ {r['name']:25s} ({r['ip']:18s})  {err}")

    if len(reachable) < 2:
        print("\n  ⚠️  Zu wenige Nodes erreichbar für Vergleich.")
        return

    # ── Block-Höhen + Chain-Gruppen ────────────────────────────────────
    chains = {}  # genesis_hash → [(name, height, latest_hash)]
    heights = {}
    for r in reachable:
        h = r.get("health", {}) or {}
        bh = h.get("block_height")
        lh = h.get("latest_hash", "?")
        ci = r.get("chain_info") or {}
        gh = ci.get("genesis_hash", h.get("genesis_hash", None))
        if bh is not None:
            heights.setdefault(bh, []).append(r["name"])
            if gh:
                chains.setdefault(gh[:16] if gh else "?", []).append((r["name"], bh, lh[:16] if lh else "?"))

    print(f"\n  ── Chain-Gruppen (gleiche Genesis = gleiche Chain) ──")
    chain_id = 0
    for gen, nodes in chains.items():
        chain_id += 1
        max_h = max(h for _, h, _ in nodes)
        print(f"    Chain #{chain_id}:  genesis={gen}…  höchster Block={max_h}")
        for name, h, lh in sorted(nodes, key=lambda x: x[1]):
            behind = f" ({max_h - h} Blöcke zurück)" if h < max_h else ""
            print(f"      ↳ {name:25s}  height={h}  latest={lh}…{behind}")

    if len(chains) > 1:
        print(f"\n  🔴 CHAIN-FORK! {len(chains)} unterschiedliche Chains im Netzwerk.")
        print(f"     Nodes auf unterschiedlichen Chains können NICHT synchronisieren.")
    else:
        print(f"\n  ✅ Alle Nodes auf derselben Chain (gleiche Genesis).")

    if len(heights) > 1:
        max_h = max(heights.keys())
        behind = [(n, h) for h, names in heights.items() if h < max_h for n in names]
        print(f"\n  ⚠️  {len(behind)} Nodes hinter der Spitze (max height={max_h}):")
        for n, h in behind:
            print(f"    - {n}: height={h} ({max_h - h} Blöcke zurück)")

    # ── DB-Metadaten ────────────────────────────────────────────────────
    print(f"\n  ── DB-Metadaten (SQLite) ──")
    for r in reachable:
        dbm = r.get("db_metadata") or {}
        if not dbm or "_error" in dbm:
            print(f"    {r['name']:25s}  Keine Sync-DB (nur HTTP erreichbar)")
            continue
        # Response hat {"ok": true, "db_metadata": {...}}
        meta = dbm.get("db_metadata", dbm)
        tc = meta.get("table_count", "?")
        oe = meta.get("oldest_entry", 0)
        ne = meta.get("newest_entry", 0)
        nid = meta.get("node_id", "")[:16]
        print(f"    {r['name']:25s}  table_count={tc:>6}  oldest={oe}  newest={ne}  node={nid}")

    # ── Peer-Vernetzung ─────────────────────────────────────────────────
    print(f"\n  ── Peer-Vernetzung (aus Sicht jeder Node) ──")
    for r in reachable:
        peers_data = r.get("peers") or {}
        peer_list = peers_data.get("peers", [])
        healthy = [p for p in peer_list if p.get("status") == "Healthy"]
        unreachable_peers = [p for p in peer_list if p.get("status") != "Healthy"]
        print(f"    {r['name']:25s}  {len(peer_list)} Peers ({len(healthy)} healthy, {len(unreachable_peers)} unreachable)")
        for p in healthy:
            print(f"      ✅ {p.get('url','?'):40s}  height={p.get('block_height','?')}  name={p.get('name','')[:20]}")
        for p in unreachable_peers:
            print(f"      ❌ {p.get('url','?'):40s}  {p.get('status','?')}  name={p.get('name','')[:20]}")

    # ── Cross-Connectivity Matrix ────────────────────────────────────────
    print(f"\n  ── Cross-Connectivity (welche Node sieht welche?) ──")
    all_ips = {r["ip"] for r in reachable}
    all_names = {r["ip"]: r["name"] for r in reachable}
    # Header
    header = f"    {'Node':25s}"
    for ip in sorted(all_ips):
        header += f" {all_names.get(ip, ip)[:12]:>13s}"
    print(header)
    for r in reachable:
        peers_data = r.get("peers") or {}
        peer_list = peers_data.get("peers", [])
        peer_urls_healthy = set()
        peer_urls_all = set()
        for p in peer_list:
            url = p.get("url", "")
            for target_ip in all_ips:
                if f"//{target_ip}:" in url:
                    peer_urls_all.add(target_ip)
                    if p.get("status") == "Healthy":
                        peer_urls_healthy.add(target_ip)
        # Auch sich selbst
        row = f"    {r['name']:25s}"
        for target_ip in sorted(all_ips):
            if target_ip == r["ip"]:
                row += f" {'🏠':>13s}"
            elif target_ip in peer_urls_healthy:
                row += f" {'✅':>13s}"
            elif target_ip in peer_urls_all:
                row += f" {'⚠️':>13s}"
            else:
                row += f" {'❌':>13s}"
        print(row)


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    network = "testnet"
    quick = False
    target_ip = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--network" and i + 1 < len(args):
            network = args[i + 1]
            i += 2
        elif args[i] == "--quick":
            quick = True
            i += 1
        elif args[i] == "--node" and i + 1 < len(args):
            target_ip = args[i + 1]
            i += 2
        elif args[i] in ("--help", "-h"):
            print(__doc__)
            return
        else:
            i += 1

    ports = PORTS[network]
    print(f"🔍 Stone Node Debugger — Network: {network.upper()}")
    print(f"   HTTP-Port: {ports['http']}  |  Sync-Port: {ports['sync']}")
    print(f"   {'Schnell-Check' if quick else 'Vollständiger Check'}")
    print()

    if target_ip:
        nodes_to_check = {target_ip: target_ip}
    else:
        nodes_to_check = dict(NODES_TOML)
        nodes_to_check["localhost"] = LOCAL_NODE

    # Parallele Checks
    results = []
    with ThreadPoolExecutor(max_workers=min(8, len(nodes_to_check))) as executor:
        futures = {
            executor.submit(check_node, ip, name, network, quick): name
            for name, ip in nodes_to_check.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({
                    "name": name,
                    "ip": nodes_to_check[name],
                    "reachable": False,
                    "health": {"_error": str(e)},
                })

    # Nach Name sortieren
    results.sort(key=lambda r: r["name"])

    # ── Zusammenfassung ─────────────────────────────────────────────────
    print("═" * 70)
    print("  📡 NODE-ÜBERSICHT")
    print("═" * 70)

    for r in results:
        h = r.get("health") or {}
        if r["reachable"]:
            bh = h.get("block_height", "?")
            lh = h.get("latest_hash", "")[:12]
            nid = h.get("node_id", "")[:16]
            print(f"  ✅ {r['name']:25s}  height={bh:>5}  hash={lh}…  node={nid}…")
        else:
            err = h.get("_error", "Timeout")
            print(f"  ❌ {r['name']:25s}  {err}")

    # ── Detail-Ansicht ──────────────────────────────────────────────────
    if not quick:
        for r in results:
            if not r["reachable"]:
                continue
            print()
            print("─" * 70)
            print(f"  📋 {r['name']} ({r['ip']})")
            print("─" * 70)

            # Chain Info
            ci = r.get("chain_info") or {}
            if ci:
                print(f"  Chain:       height={ci.get('block_height')}  "
                      f"genesis={ci.get('genesis_hash','')[:16]}…  "
                      f"latest={ci.get('latest_hash','')[:16]}…")

            # DB Metadata
            dbm = r.get("db_metadata") or {}
            meta = dbm.get("db_metadata", dbm) if "db_metadata" in dbm else dbm
            if meta.get("table_count") is not None:
                print(f"  DB (SQLite): table_count={meta.get('table_count')}  "
                      f"oldest={meta.get('oldest_entry')}  newest={meta.get('newest_entry')}")

            # Info
            info = r.get("info") or {}
            if info:
                print(f"  Node:        {info.get('node_id','')[:20]}…  "
                      f"v{info.get('version','?')}  "
                      f"peers_known={info.get('peer_count','?')}  "
                      f"healthy_peers={len(info.get('healthy_peers',[]))}")

    # Analyse
    analyze(results, network)


if __name__ == "__main__":
    main()
