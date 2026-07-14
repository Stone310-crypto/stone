#!/usr/bin/env python3
"""
StoneChain — Block-Hash Forensics
──────────────────────────────────
Vergleicht JEDEN einzelnen Block-Hash aller Nodes aus nodes.toml.
Findet den exakten Block, an dem der Fork begann.

Ausführung:
  python3 scripts/fork_forensics.py
  python3 scripts/fork_forensics.py --mainnet
"""

import subprocess, sys, json, urllib.request
from pathlib import Path
from collections import defaultdict

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



def ssh_block(host: str, user: str, port: str, api_port: int, block_idx: int) -> dict:
    """Holt einen einzelnen Block per SSH. Gibt leeres dict bei Fehler."""
    path = f"/api/v1/blocks/{block_idx}"
    return ssh_api(host, user, port, api_port, path, timeout=10)


def local_block(api_port: int, block_idx: int) -> dict:
    return api_get(f"http://127.0.0.1:{api_port}/api/v1/blocks/{block_idx}", timeout=5)


def short_hash(h: str) -> str:
    return h[:12] if h else "?"

def get_node_status(host, user, port, api_port):
    status = ssh_api(host, user, port, api_port, "/api/v1/status")
    if not status:
        return "offline"
    uptime = status.get("uptime", 0)
    peers =  status.get("peers", 0)
    return f"online (uptime: {uptime}s, peers: {peers})"


def main():
    mainnet = "--mainnet" in sys.argv
    net_tag = "mainnet" if mainnet else "testnet"
    api_port = 3180 if mainnet else 3080

    nodes_config = parse_nodes_toml(str(PROJECT_ROOT / "nodes.toml"))
    if not nodes_config:
        print(f"{R}❌ nodes.toml nicht gefunden{X}")
        sys.exit(1)

    # ── 1. Alle Nodes + deren aktuelle Höhe ermitteln ──────────────────
    print(f"{C}🔍 Nodes scouten ({net_tag})...{X}")
    node_sources: list[dict] = []  # {key, host, user, port, height, get_block_fn}

    # Lokale Node
    local_status = api_get(f"http://127.0.0.1:{api_port}/api/v1/status")
    if local_status.get("node_id"):
        h = local_status.get("chain", {}).get("block_height", 0)
        node_sources.append({
            "key": "💻 local", "height": h,
            "fetch": lambda idx, p=api_port: local_block(p, idx)
        })
        print(f"  {G}💻 local{X} → #{h}")

    # Remote Nodes
    for nd in nodes_config:
        name = nd["name"]
        host = nd["host"]
        user = nd.get("user", "root")
        port = nd.get("port", "22")
        net = nd.get("network", "both")
        if net_tag not in (net, "both"): continue

        status = ssh_api(host, user, port, api_port, "/api/v1/status")
        if not status.get("node_id"):
            print(f"  {R}☁️ {name}{X} → offline")
            continue
        h = status.get("chain", {}).get("block_height", 0)
        node_sources.append({
            "key": f"☁️ {name}", "height": h,
            "fetch": lambda idx, h=host, u=user, p=port, ap=api_port: ssh_block(h, u, p, ap, idx)
        })
        print(f"  {G}☁️ {name}{X} → #{h}")

    if len(node_sources) < 2:
        print(f"{R}❌ Mindestens 2 Nodes nötig für Vergleich{X}")
        return

    max_height = max(ns["height"] for ns in node_sources)

    print(f"\n{C}🔍 Lade Block-Hashes von {len(node_sources)} Nodes (0…{max_height})...{X}")
    print(f"   (das kann einen Moment dauern — {len(node_sources)} × {max_height+1} API-Calls)")

    # ── 2. Alle Blöcke von allen Nodes laden ───────────────────────────
    # node_hashes[node_key][block_index] = hash[:12]
    node_hashes: dict[str, dict[int, str]] = defaultdict(dict)
    node_full: dict[str, dict[int, dict]] = defaultdict(dict)  # full block data

    for ns in node_sources:
        key = ns["key"]
        max_h = ns["height"]
        for idx in range(max_h + 1):
            block = ns["fetch"](idx)
            if block and block.get("hash"):
                h = block["hash"]
                node_hashes[key][idx] = h
                node_full[key][idx] = block
                if idx % 5 == 0:
                    print(f"  {key}: Block #{idx} geladen...", end="\r")
        print(f"  {key}: {len(node_hashes[key])} Blöcke geladen{' ' * 20}")

    # ── 3. Fork-Punkt finden ───────────────────────────────────────────
    # Für jeden Block-Index: sammle alle Hashes
    all_indices = sorted(set().union(*node_hashes.values()))

    print(f"\n{W}{'═' * 110}{X}")
    print(f"{W}  🔬 BLOCK-HASH FORENSICS — {net_tag.upper()}{X}")
    print(f"{W}{'═' * 110}{X}")

    # Header
    header = f"  {'Block':<7}"
    for ns in node_sources:
        header += f" {ns['key']:<30}"
    header += f" {'Status'}"
    print(header)
    print(f"  {'─' * 108}")

    fork_found = False
    fork_block = None
    prev_consensus_hash = None

    for idx in all_indices:
        hashes_at_idx = {}
        for ns in node_sources:
            h = node_hashes[ns["key"]].get(idx)
            if h:
                hashes_at_idx[ns["key"]] = h

        if len(hashes_at_idx) < 2:
            # Nur eine Node hat diesen Block → zeige es
            line = f"  {G}#{idx:<5}{X} "
            for ns in node_sources:
                h = hashes_at_idx.get(ns["key"])
                if h:
                    line += f" {G}{short_hash(h):<30}{X}"
                else:
                    line += f" {'—':<30}"
            line += f" {D}nur 1 Node{X}"
            print(line)
            continue

        unique_hashes = set(hashes_at_idx.values())
        all_agree = len(unique_hashes) == 1

        if all_agree:
            line = f"  {G}#{idx:<5}{X} "
            for ns in node_sources:
                h = hashes_at_idx.get(ns["key"], "—")
                line += f" {G}{short_hash(h):<30}{X}"
            line += f" {G}✅{X}"
            if not fork_found:
                prev_consensus_hash = list(unique_hashes)[0]
        else:
            if not fork_found:
                fork_found = True
                fork_block = idx
            line = f"  {R}#{idx:<5}{X} "
            for ns in node_sources:
                h = hashes_at_idx.get(ns["key"], "—")
                if h in unique_hashes:
                    # Ist dieser Hash die Mehrheit oder Minderheit?
                    count = sum(1 for v in hashes_at_idx.values() if v == h)
                    if count >= len(hashes_at_idx) / 2:
                        color = G  # Mehrheit
                    else:
                        color = R  # Minderheit (fork)
                else:
                    color = R
                line += f" {color}{short_hash(h):<30}{X}"
            line += f" {R}❌ FORK!{X}"

        print(line)

    # ── 4. Fork-Zusammenfassung ──────────────────────────────────────────
    print(f"\n{W}{'═' * 110}{X}")
    print(f"{W}  📋 FORK-ANALYSE{X}")
    print(f"{W}{'═' * 110}{X}")

    if fork_found:
        print(f"\n  {R}🔴 Fork beginnt bei Block #{fork_block}{X}")
        print(f"  Davor: alle Nodes hatten identische Hashes.")
        print(f"\n  Details zu Block #{fork_block}:")

        for ns in node_sources:
            block = node_full[ns["key"]].get(fork_block)
            if not block:
                print(f"    {ns['key']}: Block NICHT vorhanden")
                continue
            h = block.get("hash", "?")
            signer = block.get("signer", "?")
            ts = block.get("timestamp", 0)
            txs = len(block.get("transactions", []))
            chat = len(block.get("chat_batches", []))
            prev = block.get("previous_hash", "?")[:12]
            print(f"    {ns['key']}:")
            print(f"      Hash:       {h[:16]}…")
            print(f"      Previous:   {prev}…")
            print(f"      Signer:     {signer}")
            print(f"      TXs:        {txs}")
            print(f"      ChatBatches: {chat}")
            print(f"      Timestamp:  {ts}")
            print(f"      Status:     {get_node_status(ns['host'], ns.get('user', 'root'), ns.get('port', '22'), api_port)}")

        # Zeige die Gruppen
        groups = defaultdict(list)
        for ns in node_sources:
            h = node_hashes[ns["key"]].get(fork_block, "N/A")
            groups[h[:16]].append(ns["key"])
        print(f"\n  {R}Fork-Gruppen ab Block #{fork_block}:{X}")
        for h, members in groups.items():
            heights = [node_hashes[m].get(node_sources[[ns["key"] for ns in node_sources].index(m)]["height"] if False else 0) for m in members]
            max_h = max((len(node_hashes[m]) - 1) for m in members)
            print(f"    Gruppe {short_hash(h)}… → {', '.join(members)} (reicht bis Block #{max_h})")

    else:
        print(f"\n  {G}✅ KEIN FORK — alle Nodes haben identische Block-Hashes!{X}")
        print(f"  Letzter gemeinsamer Block: #{max_height}")

    print(f"\n{D}{'═' * 110}{X}")


if __name__ == "__main__":
    main()
