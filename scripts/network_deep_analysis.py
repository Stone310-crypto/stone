#!/usr/bin/env python3
"""
StoneChain — Deep Network Analysis v2
──────────────────────────────────────
Nutzt /api/v1/status + /api/v1/peers (bekannte, funktionierende Endpoints).
Kartografiert das gesamte Testnet: Wer ist mit wem verbunden,
welcher PeerID gehört zu welcher Node, gibt es Forks?

Ausführung:
  python3 scripts/network_deep_analysis.py
  python3 scripts/network_deep_analysis.py --mainnet
"""

import subprocess, sys, json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
R, G, Y, C, M, B, W, D, X = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[95m", "\033[94m", "\033[1m", "\033[2m", "\033[0m"


def parse_nodes_toml(path: str) -> list[dict]:
    nodes = []; current = {}; in_node = False
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line: continue
            if line == "[[node]]":
                if in_node and current: nodes.append(current)
                current = {}; in_node = True; continue
            if "=" in line and in_node:
                k, _, v = line.partition("=")
                current[k.strip()] = v.strip().strip('"').strip("'")
    if in_node and current: nodes.append(current)
    return nodes


def ssh_api(host: str, user: str, port: str, api_port: int, path: str, timeout: int = 8) -> dict:
    cmd = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", f"{user}@{host}",
           f"curl -sf --max-time {timeout} 'http://127.0.0.1:{api_port}{path}' 2>/dev/null || echo '{{}}'"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
    except: pass
    return {}


def local_api(port: int, path: str) -> dict:
    import urllib.request
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())
    except: return {}


def short(s: str, n: int = 14) -> str:
    return (s[:n] + "…") if (s and len(s) > n) else (s or "?")


def analyze():
    mainnet = "--mainnet" in sys.argv
    net_tag = "mainnet" if mainnet else "testnet"
    api_port = 3180 if mainnet else 3080

    nodes_config = parse_nodes_toml(str(PROJECT_ROOT / "nodes.toml"))
    if not nodes_config:
        print(f"{R}❌ nodes.toml nicht gefunden oder leer{X}")
        sys.exit(1)

    # ── 1. Alle Nodes abfragen ──────────────────────────────────────────
    all_data: dict[str, dict] = {}

    # Lokale Node
    print(f"{C}🔍 Lokale Node (Port {api_port})...{X}", end=" ", flush=True)
    local_status = local_api(api_port, "/api/v1/status")
    if local_status.get("node_id"):
        local_peers = local_api(api_port, "/api/v1/peers") or []
        all_data[f"💻 local"] = _extract(local_status, local_peers, "local", "127.0.0.1", net_tag)
        print(f"{G}#{all_data['💻 local']['height']}{X}")
    else:
        print(f"{D}offline{X}")

    # Remote Nodes
    for nd in nodes_config:
        name = nd["name"]
        host = nd["host"]
        user = nd.get("user", "root")
        port = nd.get("port", "22")
        net = nd.get("network", "both")
        if net_tag not in (net, "both"): continue

        key = f"☁️ {name}"
        print(f"  📡 {key} ({host})...", end=" ", flush=True)
        status = ssh_api(host, user, port, api_port, "/api/v1/status")
        if not status.get("node_id"):
            print(f"{R}offline{X}")
            all_data[key] = {"name": name, "host": host, "height": 0, "online": False}
            continue

        peers = ssh_api(host, user, port, api_port, "/api/v1/peers") or []
        all_data[key] = _extract(status, peers, name, host, net_tag)
        print(f"{G}#{all_data[key]['height']}{X}")

    if not all_data:
        print(f"{R}Keine Nodes erreichbar{X}")
        return

    print()

    # ── 2. PeerID → Node-Name Mapping ──────────────────────────────────
    pid_map: dict[str, str] = {}
    for key, nd in all_data.items():
        pid = nd.get("peer_id", "")
        if pid and len(pid) > 12:
            pid_map[pid[:12]] = key

    # ── 3. Chain-Status Tabelle ───────────────────────────────────────
    print(f"{W}{'═' * 95}{X}")
    print(f"{W}  📊 CHAIN-STATUS — {net_tag.upper()}{X}")
    print(f"{W}{'═' * 95}{X}")
    print(f"  {'Node':<28} {'#':>5} {'Hash':<16} {'Peers':>6} {'PeerIDs gesehen':<40}")
    print(f"  {'─' * 93}")

    for key in sorted(all_data.keys()):
        nd = all_data[key]
        h = nd.get("height", 0)
        th = short(nd.get("hash", ""))
        peer_count = len(nd.get("peer_list", []))
        online = nd.get("online", True)

        if not online:
            print(f"  {R}❌{X} {key:<26} {'—':>5} {'—':<16} {'—':>6}")
            continue

        seen = []
        for p in nd.get("peer_list", []):
            pname = p.get("name", "")[:12]
            pheight = p.get("block_height", 0)
            seen.append(f"{pname}(#{pheight})")
        seen_str = ", ".join(seen[:6])
        if len(seen) > 6: seen_str += f" +{len(seen)-6}"

        print(f"  {G}●{X} {key:<26} {h:>5} {M}{th}{X} {peer_count:>6}  {D}{seen_str}{X}")

    print()

    # ── 4. Netzwerk-Topologie ──────────────────────────────────────────
    print(f"{W}{'═' * 95}{X}")
    print(f"{W}  🌐 TOPOLOGIE — Wer sieht wen?{X}")
    print(f"{W}{'═' * 95}{X}")

    connections: dict[str, set[str]] = defaultdict(set)
    for key, nd in all_data.items():
        if not nd.get("online", True): continue
        for p in nd.get("peer_list", []):
            pname = p.get("name", "")[:12]
            for nk, nd2 in all_data.items():
                if not nd2.get("online", True): continue
                if nd2.get("peer_id", "")[:12] == pname:
                    connections[key].add(nk)
                    break

    for key in sorted(all_data.keys()):
        nd = all_data[key]
        if not nd.get("online", True): continue
        conns = connections.get(key, set())
        if conns:
            targets = ", ".join(sorted(conns))
            print(f"  {key:<28} →  {G}{targets}{X}")
        else:
            print(f"  {key:<28} →  {D}(keine bekannten Nodes){X}")

    print()

    # ── 5. Unbekannte / fremde Peers ────────────────────────────────────
    print(f"{W}{'═' * 95}{X}")
    print(f"{W}  👽 FREMDE / UNBEKANNTE PEERS (nicht in nodes.toml){X}")
    print(f"{W}{'═' * 95}{X}")

    all_known_names = set()
    for nd in all_data.values():
        all_known_names.add(nd.get("peer_id", "")[:12])

    foreign = defaultdict(list)
    for key, nd in all_data.items():
        if not nd.get("online", True): continue
        for p in nd.get("peer_list", []):
            pname = p.get("name", "")[:12]
            pstatus = p.get("status", "")
            pheight = p.get("block_height", 0)
            if pname not in all_known_names and pstatus != "Unreachable":
                foreign[pname].append((key, pheight, p.get("last_hash", ""), p.get("latency_ms", "?"), p.get("url", "")))

    if foreign:
        for pname, occurrences in sorted(foreign.items()):
            heights = sorted(set(h for _, h, _, _, _ in occurrences))
            hashes = set(h[:12] for _, _, h, _, _ in occurrences if h)
            seen_by = [k for k, _, _, _, _ in occurrences]
            urls = [u for _, _, _, _, u in occurrences if u]
            max_h = max(heights) if heights else 0
            if max_h > 500:
                tag = f"{R}⚠ FREMDE CHAIN (>{max_h} blocks){X}"
            elif max_h == 0:
                tag = f"{D}leer / neu{X}"
            elif max_h < 20:
                tag = f"{Y}⏳ sync? (nur {max_h} blocks){X}"
            else:
                tag = f"{Y}? unbekannt ({max_h} blocks){X}"
            print(f"  Peer {C}{pname}…{X}")
            print(f"    Blocks: {heights}  Hash: {hashes if hashes else '?'}  Lat: {occurrences[0][3]}ms")
            print(f"    Gesehen von: {', '.join(seen_by)}")
            print(f"    URL: {urls[0] if urls else '?'}")
            print(f"    {tag}")
            print()
    else:
        print(f"  {D}(keine){X}")

    print()

    # ── 6. Fork-Erkennung + Sync-Status ──────────────────────────────────
    print(f"{W}{'═' * 95}{X}")
    print(f"{W}  🩺 HEALTH — Forks & Sync{X}")
    print(f"{W}{'═' * 95}{X}")

    hash_groups: dict[str, list[str]] = defaultdict(list)
    for key, nd in all_data.items():
        h = nd.get("hash", "")
        if h and nd.get("online", True):
            hash_groups[h[:16]].append(key)

    if len(hash_groups) == 1:
        h = next(iter(hash_groups))
        members = hash_groups[h]
        print(f"  {G}✅ Alle {len(members)} Nodes auf demselben Hash:{X} {h}…")
    else:
        print(f"  {R}⚠️  FORK! {len(hash_groups)} verschiedene Chain-Spitzen:{X}")
        for h, members in hash_groups.items():
            heights = [all_data[m]["height"] for m in members]
            print(f"    {R}✗{X} Hash {h}…  Höhen={heights}  Nodes={members}")

    online = [(k, nd) for k, nd in all_data.items() if nd.get("online", True)]
    if online:
        max_h = max(nd["height"] for _, nd in online)
        min_h = min(nd["height"] for _, nd in online)
        if max_h == min_h:
            print(f"  {G}✅ Alle auf Höhe #{max_h}{X}")
        else:
            print(f"  {Y}⏳ Höhen-Range: #{min_h} … #{max_h}{X}")
            for key, nd in online:
                if nd["height"] < max_h:
                    behind = max_h - nd["height"]
                    print(f"    {key}: #{nd['height']} ({R}-{behind}{X} Blöcke zurück)")

    total_online = len(online)
    print(f"\n  Nodes online:  {G}{total_online}{X} / {len(all_data)}")

    # ── 7. RocksDB-Vergleich via chain-inspect (nur mit --rocksdb) ─────
    if "--rocksdb" not in sys.argv:
        print(f"\n{D}  💡 Tip: --rocksdb für direkten RocksDB-Vergleich aller Nodes{X}")
        print(f"{D}{'═' * 95}{X}")
        return

    print(f"\n{W}{'═' * 95}{X}")
    print(f"{W}  🗄️  ROCKSDB DIREKT-VERGLEICH (via chain-inspect){X}")
    print(f"{W}{'═' * 95}{X}")

    # Prüfe ob chain-inspect Binary existiert
    local_bin = PROJECT_ROOT / "target" / "release" / "chain-inspect"
    if not local_bin.exists():
        print(f"  {Y}⚠️  chain-inspect binary nicht gefunden.{X}")
        print(f"  Baue mit: {D}cargo build --release --bin chain-inspect{X}")
        return

    # Auf Remote-Nodes kopieren und ausführen
    for nd in nodes_config:
        name = nd["name"]
        host = nd["host"]
        user = nd.get("user", "root")
        port = nd.get("port", "22")
        net = nd.get("network", "both")
        if net_tag not in (net, "both"): continue

        key = f"☁️ {name}"
        if not all_data.get(key, {}).get("online", True): continue

        data_dir = "stone_data" if net_tag == "testnet" else "stone_data_mainnet"
        print(f"  🔍 {key} RocksDB...", end=" ", flush=True)

        # Binary kopieren (mit Timeout-Schutz)
        try:
            scp = ["scp", "-P", str(port), "-o", "StrictHostKeyChecking=accept-new",
                   "-o", "ConnectTimeout=8", str(local_bin), f"{user}@{host}:/tmp/chain-inspect"]
            subprocess.run(scp, capture_output=True, timeout=12)
            subprocess.run(["ssh", "-p", str(port), "-o", "ConnectTimeout=5",
                            f"{user}@{host}", "chmod +x /tmp/chain-inspect"],
                           capture_output=True, timeout=8)
        except subprocess.TimeoutExpired:
            print(f"{Y}SCP-Timeout (Netzwerk langsam){X}")
            continue
        except Exception as e:
            print(f"{Y}SCP-Fehler: {e}{X}")
            continue

        # Ausführen
        try:
            result = subprocess.run(
                ["ssh", "-p", str(port), "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
                 f"{user}@{host}", f"/tmp/chain-inspect --data-dir {data_dir} --compact 2>&1"],
                capture_output=True, text=True, timeout=15
            )
        except subprocess.TimeoutExpired:
            print(f"{Y}Timeout{X}")
            continue

        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            print(f"{G}{len(lines)} Blöcke{X}")
            for line in lines[:3]:
                print(f"    {line}")
            if len(lines) > 3:
                print(f"    {D}… und {len(lines)-3} weitere{X}")
        else:
            err = (result.stderr or result.stdout).strip()[:80]
            print(f"{R}Fehler: {err}{X}")

    print()
    print(f"{D}{'═' * 95}{X}")


def _extract(status: dict, peers: list, name: str, host: str, network: str) -> dict:
    chain = status.get("chain", {})
    peer_id = ""
    # Peer-ID aus verschiedenen möglichen Feldern
    for f in ("peer_id", "p2p_peer_id", "local_peer_id"):
        if status.get(f):
            peer_id = status[f]
            break
    # Fallback: aus peers-Liste (erster peer mit unserer URL)
    if not peer_id and peers:
        for p in peers:
            if host in p.get("url", "") or "127.0.0.1" in p.get("url", ""):
                peer_id = p.get("peer_id", "")
                if peer_id: break

    return {
        "name": name, "host": host, "network": network, "online": True,
        "height": chain.get("block_height", 0),
        "hash": chain.get("latest_hash", ""),
        "node_name": status.get("node_id", ""),
        "peer_id": peer_id,
        "peer_list": peers if isinstance(peers, list) else [],
        "uptime": status.get("metrics", {}).get("uptime_secs", 0),
        "peers_total": status.get("metrics", {}).get("peers_total", 0),
    }


if __name__ == "__main__":
    analyze()
