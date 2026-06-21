#!/usr/bin/env python3
"""
QR-Login Flow Test Script — Debugging Tool.

Simuliert den gesamten QR-Login Flow und zeigt jeden Schritt:
  1. POST /api/v1/auth/qr/create  → login_token
  2. GET  /api/v1/auth/qr/status/{token} → pending/approved/expired
  3. POST /api/v1/auth/qr/approve  → genehmigt (mit Wallet-Signatur)

Kann gegen app_node (127.0.0.1:3080) oder VPS laufen.
Liest nodes.toml für VPS-Adressen.

Usage:
  python3 scripts/qr_login_test.py              # testet alle Nodes
  python3 scripts/qr_login_test.py local        # nur localhost
  python3 scripts/qr_login_test.py 212.227.54.241  # bestimmte IP
"""

import sys
import json
import time
import hashlib
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

TIMEOUT = 8

# ── Ed25519 signing (pure Python, no external deps) ──────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("⚠️  cryptography not installed — will skip signature-based approve")
    print("   pip3 install cryptography")

BAR = "─" * 80

def _get(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return {"_error": f"HTTP {e.code}", "_body": body[:500]}
    except urllib.error.URLError as e:
        return {"_error": f"Connection failed: {e.reason}"}
    except Exception as e:
        return {"_error": str(e)}

def _post(url: str, data: dict) -> dict | None:
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return {"_error": f"HTTP {e.code}", "_body": body[:500]}
    except urllib.error.URLError as e:
        return {"_error": f"Connection: {e.reason}"}
    except Exception as e:
        return {"_error": str(e)}

def gen_wallet() -> tuple[str, object]:
    """Generate test Ed25519 keypair. Returns (wallet_address, private_key)."""
    if not HAS_CRYPTO:
        return "", None
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pub_bytes.hex(), private_key

def sign_token(private_key, login_token: str) -> str:
    """Sign the login_token with the private key."""
    if not private_key:
        return ""
    return private_key.sign(login_token.encode()).hex()

def resolve_user_wallet(host: str) -> str | None:
    """Find the first user with a wallet from the local DB via sync endpoint."""
    data = _get(f"http://{host}:3080/api/v1/health")
    if not data:
        return None
    
    # Try sync-db-users on port 4002 first
    data = _get(f"http://{host}:4002/sync-db-users")
    if data and data.get("users"):
        for u in data["users"]:
            w = u.get("wallet_address", "")
            if len(w) == 64:
                return w
    return None

def get_local_wallet() -> str | None:
    """Get the wallet address from local stone.db."""
    import sqlite3
    data_dir = Path.home() / "Library/Application Support/dev.stonechain.dashboard/node_data"
    db_path = data_dir / "stone.db"
    if not db_path.exists():
        return None
    conn = sqlite3.connect(str(db_path))
    row = conn.execute(
        "SELECT wallet_address FROM users WHERE wallet_address != '' AND length(wallet_address)=64 LIMIT 1"
    ).fetchone()
    conn.close()
    return row[0] if row else None

def find_first_user_phrase(host: str) -> str | None:
    """Find the phrase hash of the first user — needed for login."""
    data = _get(f"http://{host}:4002/sync-db-users")
    if data and data.get("users"):
        for u in data["users"]:
            apikey = u.get("api_key", "")
            if apikey:
                print(f"  Found user: {u.get('name','?')} wallet={u.get('wallet_address','?')[:16]}…")
                return None  # need phrase, not api_key
    return None

def test_node(name: str, host: str, port: int = 3080):
    """Test QR-Login flow against a single node."""
    base = f"http://{host}:{port}"
    print(f"\n{BAR}")
    print(f"  Testing: {name} ({base})")
    print(f"{BAR}")

    # ── Step 0: Health check ──────────────────────────────────────────
    health = _get(f"{base}/api/v1/health")
    if not health or health.get("_error"):
        print(f"  ❌ Node unreachable: {health}")
        return
    print(f"  ✅ Health: status={health.get('status','?')} height={health.get('block_height','?')} id={health.get('node_id','?')[:20]}")

    # ── Step 1: QR-Create ─────────────────────────────────────────────
    print(f"\n  ── Step 1: QR-Create ──")
    create = _post(f"{base}/api/v1/auth/qr/create", {})
    if not create or create.get("_error"):
        print(f"  ❌ QR-Create failed: {create}")
        return

    login_token = create.get("login_token", "")
    expires_in = create.get("expires_in", "?")
    print(f"  ✅ login_token: {login_token}")
    print(f"     expires_in:  {expires_in}s")
    print(f"     QR-Code-URL: {base}/api/v1/auth/qr/status/{login_token}")

    # ── Step 2: QR-Status (pending) ───────────────────────────────────
    print(f"\n  ── Step 2: QR-Status (should be pending) ──")
    time.sleep(1)
    status = _get(f"{base}/api/v1/auth/qr/status/{login_token}")
    if not status or status.get("_error"):
        print(f"  ❌ Status-Request failed: {status}")
    else:
        s = status.get("status", "?")
        print(f"  {'✅' if s=='pending' else '❌'} status={s}")
        if s != "pending":
            print(f"     Full response: {json.dumps(status, indent=2)}")

    # ── Step 3: QR-Status (from another node perspective) ─────────────
    # Simulates what happens when app_node polls VPS after QR was created on VPS
    print(f"\n  ── Step 3: Cross-Node Polling Simulation ──")
    print(f"     (Simulating app_node asking peers for this token)")

    # ── Step 4: QR-Approve (with wallet signature) ─────────────────────
    print(f"\n  ── Step 4: QR-Approve ──")
    
    # Get a real wallet address from the local DB
    wallet_addr = get_local_wallet()
    if not wallet_addr:
        wallet_addr = resolve_user_wallet(host)
    
    if wallet_addr and HAS_CRYPTO:
        # Generate a test keypair (not the real one — just for flow testing)
        test_wallet, test_key = gen_wallet()
        sig = sign_token(test_key, login_token)
        
        approve_body = {
            "login_token": login_token,
            "wallet_address": test_wallet,
            "wallet_signature": sig,
        }
        print(f"     Using test wallet: {test_wallet[:16]}…")
        print(f"     Signature:         {sig[:32]}…")
        approve = _post(f"{base}/api/v1/auth/qr/approve", approve_body)
        if approve and not approve.get("_error"):
            ok = approve.get("ok", False)
            print(f"  {'✅' if ok else '⚠️'} approve ok={ok} (wrong signature expected)")
            print(f"     Message: {approve.get('message', approve.get('error', '?'))}")
        else:
            print(f"  ℹ️  Approve response: {approve}")
    elif wallet_addr:
        print(f"     Found wallet: {wallet_addr[:16]}… (no crypto lib — cannot sign)")
        print(f"     To test: pip3 install cryptography")
        # Try login with phrase
        users = _get(f"http://{host}:4002/sync-db-users")
        if users and users.get("users"):
            for u in users["users"][:3]:
                print(f"     User: {u.get('name','?')} wallet={u.get('wallet_address','?')[:16]}…")
    else:
        print(f"  ⚠️  No wallet found — cannot test approve")
        # Try to find users on the node
        users = _get(f"http://{host}:4002/sync-db-users")
        if users and users.get("users"):
            print(f"     Available users on {name}:")
            for u in users["users"][:5]:
                w = u.get("wallet_address", "")
                print(f"       {u.get('name','?'):20s} wallet={'none' if not w else w[:16]+'…'}")
        else:
            print(f"     No users found — is sync-port 4002 open?")

    # ── Step 5: QR-Status again ───────────────────────────────────────
    print(f"\n  ── Step 5: QR-Status (after approve attempt) ──")
    time.sleep(1)
    status2 = _get(f"{base}/api/v1/auth/qr/status/{login_token}")
    if status2 and not status2.get("_error"):
        s2 = status2.get("status", "?")
        print(f"  status={s2}")
        if s2 == "approved":
            print(f"  ✅ Approved! user_id={status2.get('user',{}).get('id','?')}")
            print(f"     session_token length: {len(status2.get('session_token',''))}")
        else:
            print(f"  (still pending — need correct wallet signature to approve)")
    else:
        print(f"  Response: {status2}")

    # ── Step 6: Test QR-Status from Peer perspective ──────────────────
    print(f"\n  ── Step 6: Cross-Node QR Status ──")
    # Check if the sync-port /qr-status/{token} endpoint works
    qr_status = _get(f"http://{host}:4002/qr-status/{login_token}")
    if qr_status and not qr_status.get("_error"):
        print(f"  ✅ Sync-Port QR-Status: {qr_status.get('status','?')}")
    else:
        print(f"  ⚠️  Sync-Port QR-Status not reachable: {qr_status}")
        print(f"     (VPS has port 4002, app_node does not)")

    # ── Summary ────────────────────────────────────────────────────────
    print(f"\n  ── Summary for {name} ──")
    print(f"  QR-Create:    {'✅' if create and not create.get('_error') else '❌'}")
    print(f"  QR-Status:    {'✅' if status and status.get('status')=='pending' else '❌'}")
    print(f"  Sync-Port QR: {'✅' if qr_status and not qr_status.get('_error') else '⚠️ (expected for app_node)'}")
    print(f"  Session lives on: {name} ({host})")
    print(f"  For cross-node: {'VPS' if qr_status else 'app_node (no sync port)'}")
    print()


def main():
    print("=" * 80)
    print("  QR-Login Flow Test")
    print("=" * 80)
    print()

    target = sys.argv[1] if len(sys.argv) > 1 else "all"

    if target == "local":
        test_node("app_node (local)", "127.0.0.1", 3080)
    elif target.replace(".", "").isdigit():
        test_node(f"VPS ({target})", target, 3080)
    else:
        # Test local
        test_node("app_node (local)", "127.0.0.1", 3080)
        
        # Test VPS nodes from nodes.toml
        nodes_path = Path(__file__).resolve().parent.parent / "nodes.toml"
        if nodes_path.exists():
            import tomllib
            with open(nodes_path, "rb") as f:
                config = tomllib.load(f)
            for n in config.get("node", []):
                if n["host"] not in ("127.0.0.1", "100.90.28.68"):
                    test_node(n["name"], n["host"], 3080)
                    break  # Just one VPS is enough
        else:
            # Fallback
            test_node("VPS (212.227.54.241)", "212.227.54.241", 3080)

    print(f"{BAR}")
    print("  Done. To test with real wallet: pip3 install cryptography")
    print("  Then re-run. QR token expires in 180s.")

if __name__ == "__main__":
    main()