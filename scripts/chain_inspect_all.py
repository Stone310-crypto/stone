#!/usr/bin/env python3
"""
chain-inspect-all — Liest die RocksDB aller Nodes aus nodes.toml und
vergleicht die Block-Hashes.

Voraussetzungen:
  - SSH-Key zu allen Nodes konfiguriert
  - chain-inspect Binary auf den Nodes vorhanden (wird automatisch deployed)
  - Python 3.10+ mit tomllib (built-in)

Ausführung:
  ./scripts/chain_inspect_all.py              # compact output
  ./scripts/chain_inspect_all.py --full        # volles JSON pro Node
  ./scripts/chain_inspect_all.py --diff        # nur Abweichungen zeigen
  ./scripts/chain_inspect_all.py --deploy      # Binary vorher bauen & deployen
"""

import subprocess
import sys
import os
import json
from pathlib import Path
from datetime import datetime, timezone

try:
    import tomllib
except ImportError:
    import tomli as tomllib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BINARY_NAME = "chain-inspect"
REMOTE_BIN = "/tmp/chain-inspect"
DATA_DIRS = {
    "testnet": "stone_data",
    "mainnet": "stone_data_mainnet",
}

# ─── Farben ────────────────────────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_nodes() -> list[dict]:
    """Liest nodes.toml und gibt alle Node-Konfigurationen zurück."""
    toml_path = PROJECT_ROOT / "nodes.toml"
    if not toml_path.exists():
        print(f"❌ {toml_path} nicht gefunden")
        sys.exit(1)
    with open(toml_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("node", [])


def build_binary() -> bool:
    """Baut das chain-inspect Binary (release)."""
    print(f"{CYAN}🔨 Baue {BINARY_NAME}...{RESET}")
    result = subprocess.run(
        ["cargo", "build", "--release", "--bin", BINARY_NAME],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        print(f"{RED}❌ Build fehlgeschlagen:{RESET}")
        print(result.stderr[-500:])
        return False
    print(f"{GREEN}✅ Build erfolgreich{RESET}")
    return True


def deploy_to_node(node: dict) -> bool:
    """Kopiert das Binary per SCP auf den Node."""
    host = node["host"]
    user = node.get("user", "root")
    port = node.get("port", "22")

    local_bin = PROJECT_ROOT / "target" / "release" / BINARY_NAME
    if not local_bin.exists():
        print(f"  {RED}Binary nicht gefunden: {local_bin}{RESET}")
        return False

    print(f"  📤 Deploye zu {user}@{host}...")
    result = subprocess.run(
        [
            "scp",
            "-P", str(port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            str(local_bin),
            f"{user}@{host}:{REMOTE_BIN}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        print(f"  {RED}❌ SCP fehlgeschlagen: {result.stderr.strip()}{RESET}")
        return False
    # chmod +x
    subprocess.run(
        ["ssh", "-p", str(port), "-o", "ConnectTimeout=10",
         f"{user}@{host}", f"chmod +x {REMOTE_BIN}"],
        capture_output=True,
        timeout=10,
    )
    print(f"  {GREEN}✅ Deployed{RESET}")
    return True


def run_remote(node: dict, network: str) -> dict | None:
    """Führt chain-inspect auf einem Node per SSH aus."""
    host = node["host"]
    user = node.get("user", "root")
    port = node.get("port", "22")
    data_dir = DATA_DIRS.get(network, "stone_data")

    cmd = f"{REMOTE_BIN} --data-dir {data_dir}"

    result = subprocess.run(
        [
            "ssh",
            "-p", str(port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15",
            f"{user}@{host}",
            cmd,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        # Exit-Code 1 = RocksDB konnte nicht öffnen (Node läuft evtl. nicht)
        if "RocksDB" in stderr or "lock" in stderr.lower():
            return {"error": "RocksDB gesperrt (Node läuft?)", "raw": stderr[:200]}
        return {"error": f"SSH/Exec-Fehler (exit={result.returncode})", "raw": stderr[:200]}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        # Vielleicht --compact output?
        return {"error": "Kein gültiges JSON", "raw": result.stdout[:500]}


def extract_block_map(data: dict) -> dict[int, str]:
    """Extrahiert { block_index → hash } aus dem JSON."""
    if "error" in data:
        return {}
    blocks = data.get("blocks", [])
    return {b["index"]: b["hash"] for b in blocks}


def format_age(ts: int) -> str:
    """Formatiert einen Unix-Timestamp als relative Zeit."""
    if ts <= 0:
        return "n/a"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    delta = now - dt
    if delta.days > 0:
        return f"{delta.days}d alt"
    hours = delta.seconds // 3600
    if hours > 0:
        return f"{hours}h alt"
    minutes = delta.seconds // 60
    return f"{minutes}m alt"


def print_comparison(
    nodes: list[dict],
    results: dict[str, dict],
    networks: list[str],
    diff_only: bool = False,
):
    """Vergleicht die Block-Hashes aller Nodes."""
    # Baue hash-map pro Node: {block_index: hash}
    node_maps: dict[str, dict[int, str]] = {}
    node_meta: dict[str, dict] = {}
    max_index = 0

    for node in nodes:
        name = node["name"]
        for net in networks:
            key = f"{name}[{net}]"
            if key in results:
                data = results[key]
                node_maps[key] = extract_block_map(data)
                node_meta[key] = {
                    "total_blocks": data.get("total_blocks", 0),
                    "latest_hash": data.get("latest_hash", "?"),
                    "genesis_hash": data.get("genesis_hash", "?"),
                    "error": data.get("error"),
                }
                if node_maps[key]:
                    max_index = max(max_index, max(node_maps[key].keys()))

    # Prüfe Genesis-Hash-Konsistenz
    genesis_hashes = set()
    for key, meta in node_meta.items():
        if meta.get("genesis_hash") and not meta.get("error"):
            genesis_hashes.add(meta["genesis_hash"])

    print()
    print(f"{BOLD}{'═' * 100}{RESET}")
    print(f"{BOLD}  StoneChain — RocksDB Block-Hash Vergleich{RESET}")
    print(f"{BOLD}{'═' * 100}{RESET}")
    print()

    # ── Genesis-Hash Check ──────────────────────────────────────────────────
    if len(genesis_hashes) > 1:
        print(f"{RED}⚠️  GENESIS-MISMATCH! Unterschiedliche Genesis-Hashes gefunden:{RESET}")
        for key, meta in node_meta.items():
            if meta.get("genesis_hash"):
                print(f"  {key}: {meta['genesis_hash'][:16]}...")
        print()
    elif len(genesis_hashes) == 1:
        gh = next(iter(genesis_hashes))
        print(f"{GREEN}✅ Genesis-Hash identisch: {gh[:16]}...{RESET}")
    else:
        print(f"{YELLOW}⚠️  Kein Genesis-Hash lesbar (Nodes laufen?){RESET}")
    print()

    # ── Summary-Tabelle ─────────────────────────────────────────────────────
    print(f"{BOLD}Node                           Blocks  Latest Hash        Status{RESET}")
    print(f"{'─' * 80}")
    for key in sorted(node_maps.keys()):
        meta = node_meta[key]
        blocks = meta["total_blocks"]
        latest = meta["latest_hash"]
        if meta.get("error"):
            status = f"{RED}❌ {meta['error'][:40]}{RESET}"
        elif blocks == 0:
            status = f"{YELLOW}⚠️  Leere DB{RESET}"
        else:
            status = f"{GREEN}✅ OK{RESET}"
        print(f"  {key:<30} {blocks:>6}  {latest[:16]}...  {status}")

    # ── Block-Hash-Vergleich ─────────────────────────────────────────────────
    all_indices = sorted(set().union(*node_maps.values()))
    if not all_indices:
        print(f"\n{YELLOW}Keine Blöcke zum Vergleichen.{RESET}")
        return

    mismatches = 0
    shown = 0

    print(f"\n{BOLD}Block-Hash-Vergleich (pro Index):{RESET}")
    print(f"{'─' * 100}")

    for idx in all_indices:
        hashes_at_idx: dict[str, str] = {}
        for key, bmap in node_maps.items():
            if idx in bmap:
                h = bmap[idx]
                hashes_at_idx[key] = h[:16]

        if not hashes_at_idx:
            continue

        unique_hashes = set(hashes_at_idx.values())

        if diff_only and len(unique_hashes) <= 1:
            continue

        shown += 1
        if len(unique_hashes) > 1:
            mismatches += 1
            print(f"  {RED}Block #{idx:<4} ❌ MISMATCH:{RESET}")
        else:
            print(f"  {GREEN}Block #{idx:<4} ✅{RESET}  {next(iter(unique_hashes))}...")

        # Zeige pro Node
        for key in sorted(hashes_at_idx.keys()):
            h = hashes_at_idx[key]
            consensus = len(unique_hashes) == 1
            marker = f"{GREEN}  ✓{RESET}" if consensus else f"{RED}  ✗{RESET}"
            print(f"    {marker} {key:<30} {h}...")

    print(f"\n{BOLD}Ergebnis:{RESET} {shown} Blöcke verglichen, {mismatches} mismatches")

    if mismatches == 0 and shown > 0:
        print(f"{GREEN}✅ Alle Nodes haben identische Block-Hashes!{RESET}")
        print(f"{GREEN}   Chain ist konsistent über {len(node_maps)} Nodes.{RESET}")


def main():
    args = sys.argv[1:]
    full_output = "--full" in args
    diff_only = "--diff" in args
    do_deploy = "--deploy" in args
    network_filter = "testnet" if "--mainnet" not in args else "mainnet"

    nodes = load_nodes()
    if not nodes:
        print("❌ Keine Nodes in nodes.toml gefunden")
        sys.exit(1)

    # Netzwerke bestimmen
    networks = []
    for node in nodes:
        net = node.get("network", "both")
        if net in ("testnet", "both") and network_filter == "testnet":
            if "testnet" not in networks:
                networks.append("testnet")
        if net in ("mainnet", "both") and network_filter == "mainnet":
            if "mainnet" not in networks:
                networks.append("mainnet")

    # Binary bauen & deployen
    if do_deploy:
        if not build_binary():
            sys.exit(1)
        print()
        for node in nodes:
            net = node.get("network", "both")
            if net == network_filter or net == "both":
                print(f"{BOLD}{node['name']}{RESET} ({node['host']})")
                deploy_to_node(node)
        print()

    # Auf allen Nodes ausführen
    results: dict[str, dict] = {}
    for node in nodes:
        net = node.get("network", "both")
        targets = []
        if net in ("testnet", "both") and "testnet" in networks:
            targets.append("testnet")
        if net in ("mainnet", "both") and "mainnet" in networks:
            targets.append("mainnet")

        for target_net in targets:
            key = f"{node['name']}[{target_net}]"
            host = node["host"]
            print(f"  🔍 {key} ({host})...", end=" ", flush=True)
            data = run_remote(node, target_net)
            if data:
                results[key] = data
                if "error" in data:
                    print(f"{RED}Fehler: {data['error'][:60]}{RESET}")
                else:
                    blocks = data.get("total_blocks", 0)
                    latest = data.get("latest_hash", "?")[:16]
                    print(f"{GREEN}{blocks} Blöcke, latest={latest}...{RESET}")
            else:
                print(f"{RED}Keine Antwort{RESET}")

    if full_output:
        print(f"\n{BOLD}{'═' * 100}{RESET}")
        print(f"{BOLD}  Volles JSON{RESET}")
        print(f"{BOLD}{'═' * 100}{RESET}")
        for key, data in sorted(results.items()):
            print(f"\n─── {key} ───")
            print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print_comparison(nodes, results, networks, diff_only=diff_only)


if __name__ == "__main__":
    main()
