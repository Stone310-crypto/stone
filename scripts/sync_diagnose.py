#!/usr/bin/env python3
"""
StoneChain — Sync Connectivity Matrix
──────────────────────────────────────
Zeigt für jeden Node in nodes.toml:
  • Eigene Block-Höhe + Hash
  • Welche Peers er kennt
  • Ob er sie erreichen kann (Health-Check)
  • Ob sie mehr Blöcke haben (= sync-würdig)
  • Kreuzmatrix: Wer erreicht wen?

Ausführung:
  python3 scripts/sync_diagnose.py
  python3 scripts/sync_diagnose.py --trigger   # Force-Sync auf allen Nodes
  python3 scripts/sync_diagnose.py --mainnet
"""

import subprocess, sys, json, urllib.request
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
R, G, Y, C, M, W, D, X = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[95m", "\033[1m", "\033[2m", "\033[0m"


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


def api_get(url: str, timeout: int = 5) -> dict:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except: return {}


def ssh_get(host: str, user: str, port: str, url: str, timeout: int = 8) -> dict:
    cmd = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", f"{user}@{host}",
           f"curl -sf --max-time {timeout} '{url}' 2>/dev/null || echo '{{}}'"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
    except: pass
    return {}


def short(s: str, n: int = 12) -> str:
    return (s[:n] + "…") if (s and len(s) > n) else (s or "?")


def ts_ago(ts) -> str:
    if not ts or ts <= 0: return "nie"
    d = datetime.fromtimestamp(ts, tz=timezone.utc)
    s = (datetime.now(tz=timezone.utc) - d).total_seconds()
    if s > 86400: return f"{int(s//86400)}d"
    if s > 3600: return f"{int(s//3600)}h"
    return f"{int(s//60)}m"


def main():
    mainnet = "--mainnet" in sys.argv
    do_trigger = "--trigger" in sys.argv
    net_tag = "mainnet" if mainnet else "testnet"
    api_port = 3180 if mainnet else 3080
    sync_port = 4002

    nodes_config = parse_nodes_toml(str(PROJECT_ROOT / "nodes.toml"))

    # ── 1. Alle Nodes sammeln ──────────────────────────────────────────
    all_nodes: dict[str, dict] = {}

    # Lokal
    local_status = api_get(f"http://127.0.0.1:{api_port}/api/v1/status")
    if local_status.get("node_id"):
        all_nodes["💻 local"] = {
            "key": "💻 local", "host": "127.0.0.1", "api_port": api_port,
            "sync_port": sync_port, "is_local": True,
            "status": local_status, "peers": api_get(f"http://127.0.0.1:{api_port}/api/v1/peers") or [],
            "sync_peers": api_get(f"http://127.0.0.1:{sync_port}/peers") or {},
        }

    # Remote
    for nd in nodes_config:
        name = nd["name"]
        host = nd["host"]
        user = nd.get("user", "root")
        port = nd.get("port", "22")
        net = nd.get("network", "both")
        if net_tag not in (net, "both"): continue

        status = ssh_get(host, user, port, f"http://127.0.0.1:{api_port}/api/v1/status")
        if not status.get("node_id"): continue

        peers = ssh_get(host, user, port, f"http://127.0.0.1:{api_port}/api/v1/peers") or []
        sync_peers = ssh_get(host, user, port, f"http://127.0.0.1:{sync_port}/peers") or {}

        all_nodes[f"☁️ {name}"] = {
            "key": f"☁️ {name}", "host": host, "api_port": api_port,
            "sync_port": sync_port, "is_local": False,
            "status": status, "peers": peers, "sync_peers": sync_peers,
            "ssh_user": user, "ssh_port": port,
        }

    if len(all_nodes) < 2:
        print(f"{R}Mindestens 2 Nodes für Analyse nötig{X}")
        return

    # ── 2. Konnektivitäts-Matrix ────────────────────────────────────────
    # Map: host → node_key
    host_to_key = {}
    for key, nd in all_nodes.items():
        host_to_key[nd["host"]] = key
        # Auch IPs aus peers mappen
        for p in nd["peers"]:
            if "url" in p:
                h = p["url"].replace("http://", "").replace("https://", "").split(":")[0]
                if h not in host_to_key:
                    host_to_key[h] = None  # unknown

    print(f"{W}{'═' * 110}{X}")
    print(f"{W}  🔗 SYNC KONNEKTIVITÄTS-MATRIX — {net_tag.upper()}{X}")
    print(f"{W}{'═' * 110}{X}")
    print()
    print(f"  {'Node':<22} {'#':>5} {'Hash':<14} {'Erreicht':<38} {'Sync-Quelle':<30}")
    print(f"  {'─' * 108}")

    for key in sorted(all_nodes.keys()):
        nd = all_nodes[key]
        chain = nd["status"].get("chain", {})
        h = chain.get("block_height", 0)
        th = short(chain.get("latest_hash", ""))

        # Prüfe welche Peers erreichbar sind
        reachable = []
        unreachable = []
        for p in nd["peers"]:
            pstatus = p.get("status", "")
            ph = p.get("block_height", 0)
            purl = p.get("url", "")
            if pstatus == "Healthy":
                reachable.append((purl, ph))
            elif pstatus == "Unreachable":
                unreachable.append((purl, ph))

        # Wer hat mehr Blöcke?
        best_peer = max((p.get("block_height", 0) for p in nd["peers"]), default=0)
        has_source = best_peer > h

        # Darstellung
        r_str = ", ".join(f"{G}{short(u.split('://')[1].split(':')[0])}(#{ph}){X}" for u, ph in reachable[:3])
        if len(reachable) > 3: r_str += f" +{len(reachable)-3}"
        u_str = ", ".join(f"{R}{short(u.split('://')[1].split(':')[0])}(#{ph}){X}" for u, ph in unreachable[:2])
        if len(unreachable) > 2: u_str += f" +{len(unreachable)-2}"

        all_status = r_str
        if u_str:
            all_status += (" | " if r_str else "") + u_str

        sync_info = ""
        if has_source and reachable:
            sync_info = f"{G}✅ von {short(reachable[0][0].split('://')[1].split(':')[0])}{X} (#{h}→#{best_peer})"
        elif has_source:
            sync_info = f"{Y}⏳ Quelle da, aber Unreachable{X}"
        elif best_peer == 0:
            sync_info = f"{D}keine Quelle{X}"
        else:
            sync_info = f"{G}auf Höhe{X}"

        print(f"  {key:<22} {h:>5} {M}{th}{X}  {all_status:<50} {sync_info}")

    print()

    # ── 3. Kreuz-Matrix: Wer kann wen pingen? ──────────────────────────
    print(f"{W}  📡 CROSS-CONNECTIVITY (HTTP Port {api_port}):{X}")
    print(f"  {'':<22}", end="")
    for key in sorted(all_nodes.keys()):
        print(f" {key:<22}", end="")
    print()

    for key_from in sorted(all_nodes.keys()):
        nd_from = all_nodes[key_from]
        print(f"  {key_from:<22}", end="")
        for key_to in sorted(all_nodes.keys()):
            nd_to = all_nodes[key_to]
            if key_from == key_to:
                print(f" {'─':<22}", end="")
                continue

            # Prüfe ob key_from key_to in seiner Peer-Liste hat und ob Healthy
            target_host = nd_to["host"]
            found = None
            for p in nd_from["peers"]:
                if target_host in p.get("url", ""):
                    found = p
                    break

            if found:
                status = found.get("status", "")
                if status == "Healthy":
                    print(f" {G}✅ Healthy{X}", end=" " * (22 - 11))
                else:
                    print(f" {R}❌ {status}{X}", end=" " * (22 - len(status) - 4))
            else:
                # Direct check: can we HTTP GET the other node?
                if nd_from.get("is_local"):
                    health = api_get(f"http://{target_host}:{api_port}/api/v1/health", timeout=3)
                else:
                    health = ssh_get(
                        nd_from["host"], nd_from.get("ssh_user", "root"),
                        nd_from.get("ssh_port", "22"),
                        f"http://{target_host}:{api_port}/api/v1/health", timeout=5
                    )
                if health.get("status") == "ok" or health.get("block_height"):
                    print(f" {G}🌐 direkt{X}", end=" " * (22 - 11))
                else:
                    print(f" {R}🚫 nichts{X}", end=" " * (22 - 11))
        print()

    print()

    # ── 4. Sync-Port (4002) Peers ───────────────────────────────────────
    print(f"{W}  🔌 SYNC-PORT PEERS (Port {sync_port}):{X}")
    for key in sorted(all_nodes.keys()):
        nd = all_nodes[key]
        sp = nd.get("sync_peers", {})
        peers = sp.get("peers", [])
        healthy = [p for p in peers if p.get("status") == "Healthy"]
        unreachable = [p for p in peers if p.get("status") == "Unreachable"]
        print(f"  {key:<22}  {G}{len(healthy)} healthy{X}  {R}{len(unreachable)} unreachable{X}", end="")
        for p in unreachable[:2]:
            print(f"  [{R}{short(p.get('url',''))}{X}]", end="")
        print()

    print()

    # ── 5. Empfehlungen ─────────────────────────────────────────────────
    print(f"{W}{'═' * 110}{X}")
    print(f"{W}  🩺 DIAGNOSE & EMPFEHLUNGEN{X}")
    print(f"{W}{'═' * 110}{X}")

    # Finde Nodes mit Unreachable-Peers die mehr Blöcke haben
    issues = []
    for key, nd in all_nodes.items():
        h = nd["status"].get("chain", {}).get("block_height", 0)
        for p in nd["peers"]:
            ph = p.get("block_height", 0)
            pstatus = p.get("status", "")
            if pstatus == "Unreachable" and ph > h:
                issues.append(f"  {R}⚠️{X}  {key} (#{h}) kann Sync-Quelle {short(p['url'])} (#{ph}) NICHT erreichen")
            if pstatus == "Healthy" and ph > h:
                issues.append(f"  {G}💡{X}  {key} (#{h}) → sync von {short(p['url'])} (#{ph}) möglich")

    if issues:
        for issue in issues:
            print(issue)
    else:
        print(f"  {G}✅ Keine offensichtlichen Sync-Probleme{X}")

    # Max height
    max_h = max(nd["status"].get("chain", {}).get("block_height", 0) for nd in all_nodes.values())
    behind = [(key, nd["status"].get("chain", {}).get("block_height", 0))
              for key, nd in all_nodes.items()
              if nd["status"].get("chain", {}).get("block_height", 0) < max_h]

    if behind:
        print(f"\n  {Y}Nodes mit Rückstand:{X}")
        for key, h in behind:
            print(f"    {key}: #{h} (↳ {max_h - h} Blöcke)")

    # Force-Sync Hinweis
    if do_trigger:
        print(f"\n  {C}⚡ Trigger Force-Sync...{X}")
        for key, nd in all_nodes.items():
            if nd.get("is_local"):
                result = api_get(f"http://127.0.0.1:{api_port}/api/v1/sync", timeout=3)
            else:
                result = {}
            print(f"    {key}: Sync angestoßen")

    print(f"\n  {D}Force-Sync manuell:{X}")
    print(f"  {D}curl -X POST http://<node>:{api_port}/api/v1/sync \\{X}")
    print(f"  {D}  -H 'x-api-key: <admin-key>' -H 'Content-Type: application/json' -d '{{}}'{X}")
    print(f"\n  {D}Unreachable Peers löschen:{X}")
    print(f"  {D}curl -X DELETE http://<node>:{api_port}/api/v1/peers/<idx>{X}")
    print()
    print(f"{D}{'═' * 110}{X}")


if __name__ == "__main__":
    main()
