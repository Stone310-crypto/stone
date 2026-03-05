#!/usr/bin/env python3
"""
Test: QR-Code Login Flow.

Simuliert den vollständigen Cross-Device Login:
1. Website erstellt QR-Session → login_token
2. Website pollt Status → "pending"
3. iOS App genehmigt QR-Login (mit Bearer-Token)
4. Website pollt erneut → "approved" mit session_token + user
5. Website benutzt neuen Session-Token

Voraussetzung: Ein User muss bereits registriert sein (test_auth.py).
"""
import hashlib
import sys
import time
import requests

SERVER = "http://212.227.54.241:8080"
# Bereits registrierter User (aus test_auth.py)
PHRASE = "purchase scatter radar cannon elevator toast input salt drip jungle tumble cable"


def derive_keys(phrase: str):
    from mnemonic import Mnemonic
    from nacl.signing import SigningKey
    m = Mnemonic("english")
    entropy = m.to_entropy(phrase)
    key_bytes = hashlib.sha256(entropy).digest() if len(entropy) < 32 else bytes(entropy[:32])
    signing_key = SigningKey(key_bytes)
    wallet = signing_key.verify_key.encode().hex()
    return signing_key, wallet


def get_bearer_token(signing_key, wallet: str) -> str:
    """Holt einen Bearer-Token via Challenge-Response."""
    resp = requests.post(f"{SERVER}/api/v1/auth/challenge", json={"wallet_address": wallet})
    nonce = resp.json()["challenge"]
    sig = signing_key.sign(nonce.encode()).signature.hex()
    resp = requests.post(f"{SERVER}/api/v1/auth/verify",
                         json={"wallet_address": wallet, "signature": sig})
    return resp.json()["session_token"]


def main():
    print("=== QR-Code Login Test ===\n")

    # Vorbereitung: Bearer-Token für "iOS App" holen
    signing_key, wallet = derive_keys(PHRASE)
    print(f"[0] Vorbereitung: Bearer-Token für iOS-App holen...")
    bearer = get_bearer_token(signing_key, wallet)
    print(f"    Bearer: {bearer[:30]}...\n")

    # Step 1: Website erstellt QR-Session
    print(f"[1] Website: POST /auth/qr/create")
    resp = requests.post(f"{SERVER}/api/v1/auth/qr/create")
    print(f"    Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        return
    data = resp.json()
    login_token = data["login_token"]
    expires_in = data["expires_in"]
    print(f"    login_token: {login_token[:20]}...")
    print(f"    expires_in: {expires_in}s")
    print(f"    → QR-Code würde diesen Token enthalten\n")

    # Step 2: Website pollt Status (sollte "pending" sein)
    print(f"[2] Website: GET /auth/qr/status/{login_token[:16]}...")
    resp = requests.get(f"{SERVER}/api/v1/auth/qr/status/{login_token}")
    print(f"    Status: {resp.status_code}")
    status = resp.json()
    print(f"    QR-Status: {status['status']}")
    assert status["status"] == "pending", f"Erwartet 'pending', bekam '{status['status']}'"
    print(f"    ✓ Noch nicht gescannt\n")

    # Step 3: iOS App genehmigt (nach QR-Scan + FaceID)
    print(f"[3] iOS App: POST /auth/qr/approve (mit Bearer-Token)")
    resp = requests.post(
        f"{SERVER}/api/v1/auth/qr/approve",
        json={"login_token": login_token},
        headers={"Authorization": f"Bearer {bearer}"}
    )
    print(f"    Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        return
    approve_data = resp.json()
    print(f"    ok: {approve_data['ok']}")
    print(f"    message: {approve_data['message']}")
    print(f"    ✓ Login genehmigt!\n")

    # Step 4: Website pollt erneut (sollte "approved" mit Token sein)
    print(f"[4] Website: GET /auth/qr/status/{login_token[:16]}... (Poll)")
    resp = requests.get(f"{SERVER}/api/v1/auth/qr/status/{login_token}")
    print(f"    Status: {resp.status_code}")
    data = resp.json()
    print(f"    QR-Status: {data['status']}")
    assert data["status"] == "approved", f"Erwartet 'approved', bekam '{data['status']}'"
    session_token = data["session_token"]
    user = data["user"]
    api_key = data.get("api_key", "")
    print(f"    session_token: {session_token[:30]}...")
    print(f"    api_key: {api_key[:20]}...")
    print(f"    User: {user['name']} ({user['id']})")
    print(f"    Wallet: {user['wallet_address'][:20]}...")
    print(f"    ✓ Website hat Token erhalten!\n")

    # Step 5: Website nutzt den erhaltenen Session-Token
    print(f"[5] Website: GET /status (mit neuem Session-Token)")
    resp = requests.get(
        f"{SERVER}/api/v1/status",
        headers={"Authorization": f"Bearer {session_token}"}
    )
    print(f"    Status: {resp.status_code}")
    assert resp.status_code == 200, f"Auth fehlgeschlagen: {resp.text}"
    print(f"    ✓ Authentifiziert!\n")

    # Step 6: Verify Session ist verbraucht (Replay-Schutz)
    print(f"[6] Replay-Check: Nochmal /auth/qr/status abfragen...")
    resp = requests.get(f"{SERVER}/api/v1/auth/qr/status/{login_token}")
    print(f"    Status: {resp.status_code}")
    print(f"    Response: {resp.json()}")
    assert resp.status_code in (404, 410), "Session sollte verbraucht sein"
    print(f"    ✓ Session verbraucht (Replay-Schutz)\n")

    print("=== ALLE 6 SCHRITTE BESTANDEN ===")


if __name__ == "__main__":
    main()
