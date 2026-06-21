#!/usr/bin/env python3
"""
StoneChain Full DB Inspector — Lokale + Remote-Daten vollständig prüfen.

Liest:
  - Lokale stone.db, pending.json, chat_index.json
  - Remote nodes via HTTP (sync port 4002)

Zeigt:
  - Messages mit Inhalt, Sender/Empfänger, Timestamp, Status
  - Conversations (ChatIndex) mit Teilnehmern
  - Users mit Wallets
  - Sync-Vergleich zwischen Nodes
"""

import tomllib
import sys
import urllib.request
import urllib.error
import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

SYNC_PORT = 4002
TIMEOUT = 8
BAR = "─" * 90

# ── helpers ────────────────────────────────────────────────────────────

def _get(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read().decode()
            return json.loads(raw)
    except Exception:
        return None

def ts_str(ts) -> str:
    if not ts or ts == 0:
        return "n/a"
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except:
        return str(ts)

def short(s, n=30):
    s = str(s) if s else ""
    return s if len(s) <= n else s[:n-3] + "…"


# ── local readers ──────────────────────────────────────────────────────

def read_local_sqlite(data_dir: str) -> dict:
    """Read stone.db directly."""
    db_path = os.path.join(data_dir, "stone.db")
    result = {"users": [], "messages": [], "peers": []}
    if not os.path.exists(db_path):
        result["error"] = "stone.db not found"
        return result

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute("SELECT id, name, wallet_address FROM users ORDER BY name").fetchall()
        result["users"] = [dict(r) for r in rows]
    except:
        result["users"] = []

    try:
        rows = conn.execute(
            "SELECT msg_id, sequence, from_wallet, to_wallet, from_name, encrypted_content, "
            "nonce, timestamp, signature, pow_nonce, status FROM message_pool ORDER BY timestamp DESC"
        ).fetchall()
        result["messages"] = [dict(r) for r in rows]
    except:
        result["messages"] = []

    try:
        rows = conn.execute("SELECT url, name, status, block_height FROM peers ORDER BY block_height DESC").fetchall()
        result["peers"] = [dict(r) for r in rows]
    except:
        result["peers"] = []

    conn.close()
    return result


def read_local_json(data_dir: str) -> dict:
    """Read chat_index.json and pending.json."""
    result = {"chat_conversations": {}, "pending_messages": []}

    ci_path = os.path.join(data_dir, "chat_index.json")
    if os.path.exists(ci_path):
        try:
            with open(ci_path) as f:
                ci = json.load(f)
            result["chat_conversations"] = ci.get("conversations", {})
        except:
            pass

    mp_path = os.path.join(data_dir, "message_pool", "pending.json")
    if os.path.exists(mp_path):
        try:
            with open(mp_path) as f:
                pending = json.load(f)
            result["pending_messages"] = pending
        except:
            pass

    return result


def fetch_remote(host: str) -> dict:
    base = f"http://{host}:{SYNC_PORT}"
    r = {}
    d = _get(f"{base}/db-metadata")
    r["meta"] = d.get("db_metadata") if d else None
    d = _get(f"{base}/message-pool")
    r["messages"] = d.get("messages", []) if d else []
    r["messages_count"] = d.get("count", len(r["messages"])) if d else 0
    d = _get(f"{base}/sync-db-users")
    r["users"] = d.get("users", []) if d else []
    d = _get(f"{base}/sync-db-peers")
    r["peers"] = d.get("peers", []) if d else []
    return r


# ── display ────────────────────────────────────────────────────────────

def print_messages(title: str, messages: list, max_show: int = 20):
    if not messages:
        print(f"  {title}: keine Nachrichten")
        return

    print(f"\n{'─'*90}")
    print(f"  💬 {title} ({len(messages)} total)")
    print(f"{'─'*90}")
    print(f"  {'Time':<17s} {'From':>16s} → {'To':<16s} {'Content':>12s} {'Seq':>4s} {'Status':<12s}")
    print(f"  {'─'*17} {'─'*16}   {'─'*16} {'─'*12} {'─'*4} {'─'*12}")

    for m in messages[:max_show]:
        ts = ts_str(m.get("timestamp", 0))
        fw = short(m.get("from_wallet", ""), 14)
        tw = short(m.get("to_wallet", ""), 14)
        content = short(m.get("encrypted_content", ""), 10)
        seq = m.get("sequence", "?")
        status = m.get("status", "?")
        if isinstance(status, dict):
            status = list(status.keys())[0] if status else "?"
        print(f"  {ts:<17s} {fw:>16s} → {tw:<16s} {content:>12s} {str(seq):>4s} {str(status):<12s}")

    if len(messages) > max_show:
        print(f"  … und {len(messages) - max_show} weitere")


def print_users(title: str, users: list, max_show: int = 10):
    if not users:
        print(f"  {title}: keine User")
        return
    print(f"\n{'─'*90}")
    print(f"  📋 {title} ({len(users)} total)")
    print(f"{'─'*90}")
    print(f"  {'Name':<25s} {'Wallet':>18s}")
    print(f"  {'─'*25} {'─'*18}")
    for u in users[:max_show]:
        name = short(u.get("name", "?"), 23)
        wallet = short(u.get("wallet_address", u.get("wallet", "")), 16)
        print(f"  {name:<25s} {wallet:>18s}")
    if len(users) > max_show:
        print(f"  … und {len(users) - max_show} weitere")


# ── main ───────────────────────────────────────────────────────────────

def main():
    script_dir = Path(__file__).resolve().parent
    nodes_path = script_dir.parent / "nodes.toml"

    # ── 1. Local DB ───────────────────────────────────────────────────
    local_data_dir = os.path.expanduser("~/Library/Application Support/dev.stonechain.dashboard/node_data")

    print("=" * 90)
    print("  StoneChain Full DB Inspector")
    print("=" * 90)
    print()
    print(f"{BAR}")
    print("  LOCAL DATABASE")
    print(f"{BAR}")
    print(f"  Path: {local_data_dir}")
    print()

    local_sql = read_local_sqlite(local_data_dir)
    local_json = read_local_json(local_data_dir)

    # Messages from SQLite
    print_messages("Local SQLite — message_pool", local_sql.get("messages", []))

    # Conversations from chat_index.json
    convs = local_json.get("chat_conversations", {})
    if convs:
        print(f"\n{'─'*90}")
        print(f"  📁 ChatIndex Conversations ({len(convs)} total)")
        print(f"{'─'*90}")
        for key, entries in convs.items():
            parts = key.split(":", 1)
            a = short(parts[0], 16) if len(parts) > 0 else "?"
            b = short(parts[1], 16) if len(parts) > 1 else "?"
            print(f"  {a} ↔ {b}: {len(entries)} messages")
            for e in entries[:3]:
                ts = ts_str(e.get("timestamp", 0))
                print(f"    {ts}  block={e.get('block_index','?')}  msg_id={short(e.get('msg_id',''), 20)}")
            if len(entries) > 3:
                print(f"    … {len(entries) - 3} more")
    else:
        print(f"  📁 ChatIndex: no conversations")

    # Users
    print_users("Local Users (SQLite)", local_sql.get("users", []))

    # Local Peers
    peers = local_sql.get("peers", [])
    if peers:
        print(f"\n{'─'*90}")
        print(f"  🌐 Local Peers ({len(peers)} total)")
        print(f"{'─'*90}")
        for p in peers:
            print(f"  {short(p.get('url','?'), 50):<50s} status={p.get('status','?')} height={p.get('block_height','?')}")

    # ── 2. Remote Nodes ──────────────────────────────────────────────
    print(f"\n{BAR}")
    print("  REMOTE NODES")
    print(f"{BAR}")

    if not nodes_path.exists():
        print(f"  ⚠️  nodes.toml not found at {nodes_path} — skipping remote check")
    else:
        with open(nodes_path, "rb") as f:
            config = tomllib.load(f)
        nodes = config.get("node", [])

        for n in nodes:
            name, host = n["name"], n["host"]
            print(f"\n  📥 Fetching {name} ({host}) …", end=" ", flush=True)
            data = fetch_remote(host)
            if data.get("meta"):
                m = data["meta"]
                print(f"✅ entries={m.get('table_count',0)} msgs={data.get('messages_count',0)} users={len(data.get('users',[]))}")
                print_messages(f"  {name} — messages", data.get("messages", []), max_show=10)
                # Show message comparison with local
                local_msg_ids = {m.get("msg_id", "") for m in local_sql.get("messages", [])}
                remote_msg_ids = {m.get("msg_id", "") for m in data.get("messages", [])}
                only_remote = remote_msg_ids - local_msg_ids
                only_local = local_msg_ids - remote_msg_ids
                if only_remote:
                    print(f"    ⚠️  {len(only_remote)} msgs only on {name} (not local)")
                if only_local:
                    print(f"    ⚠️  {len(only_local)} msgs only local (not on {name})")
                if not only_remote and not only_local and local_msg_ids:
                    print(f"    ✅ Message IDs fully synced with {name}")

                # Compare users
                local_user_wallets = {u.get("wallet_address", "") for u in local_sql.get("users", [])}
                remote_user_wallets = {u.get("wallet_address", "") for u in data.get("users", [])}
                only_remote_u = remote_user_wallets - local_user_wallets
                only_local_u = local_user_wallets - remote_user_wallets
                if only_remote_u:
                    print(f"    ⚠️  {len(only_remote_u)} users only on {name}")
                if only_local_u:
                    print(f"    ⚠️  {len(only_local_u)} users only local")
                if not only_remote_u and not only_local_u:
                    print(f"    ✅ Users fully synced with {name}")
            else:
                print("❌ unreachable")

    print(f"\n{BAR}")
    print()


if __name__ == "__main__":
    main()