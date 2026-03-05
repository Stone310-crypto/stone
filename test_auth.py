#!/usr/bin/env python3
"""
Test-Script: Vollständiger Challenge-Response Auth Flow.
Simuliert den Client (App/Website) der sich mit Seed-Phrase anmeldet.

Flow:
1. Seed-Phrase → Ed25519 Signing Key ableiten
2. POST /auth/challenge mit wallet_address → Nonce erhalten
3. Nonce mit Private Key signieren
4. POST /auth/verify mit wallet_address + signature → Session Token erhalten
5. Authenticated Request mit Bearer Token testen
"""

import hashlib
import json
import subprocess
import sys
import requests

SERVER = "http://212.227.54.241:8080"
PHRASE = "purchase scatter radar cannon elevator toast input salt drip jungle tumble cable"

def derive_keys_from_phrase(phrase: str):
    """
    Leitet Ed25519 Schlüsselpaar aus BIP39 Mnemonic ab.
    Gleiche Logik wie in Rust: mnemonic → entropy → SHA-256(entropy) → Ed25519 SigningKey
    """
    try:
        from mnemonic import Mnemonic
        m = Mnemonic("english")
        entropy = m.to_entropy(phrase)
    except ImportError:
        print("Installiere: pip3 install mnemonic")
        sys.exit(1)
    
    # Wenn entropy < 32 bytes → SHA-256 expandieren (gleich wie Rust-Code)
    if len(entropy) < 32:
        key_bytes = hashlib.sha256(entropy).digest()
    else:
        key_bytes = bytes(entropy[:32])
    
    try:
        from nacl.signing import SigningKey
        signing_key = SigningKey(key_bytes)
        verify_key = signing_key.verify_key
        wallet_address = verify_key.encode().hex()
        return signing_key, wallet_address
    except ImportError:
        print("Installiere: pip3 install PyNaCl")
        sys.exit(1)


def main():
    print(f"=== Stone Auth: Challenge-Response Test ===\n")
    
    # 1. Keys aus Phrase ableiten
    print(f"[1] Seed-Phrase: {PHRASE[:30]}...")
    signing_key, wallet_address = derive_keys_from_phrase(PHRASE)
    print(f"    Wallet: {wallet_address}")
    
    # 2. Challenge anfordern
    print(f"\n[2] Challenge anfordern...")
    resp = requests.post(f"{SERVER}/api/v1/auth/challenge", 
                         json={"wallet_address": wallet_address})
    print(f"    Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        return
    
    data = resp.json()
    nonce = data["challenge"]
    print(f"    Nonce: {nonce}")
    print(f"    Expires in: {data['expires_in']}s")
    
    # 3. Nonce signieren
    print(f"\n[3] Challenge signieren...")
    signed = signing_key.sign(nonce.encode())
    signature = signed.signature.hex()
    print(f"    Signature: {signature[:40]}...")
    
    # 4. Signature verifizieren lassen & Token erhalten
    print(f"\n[4] Verify (Signature senden, Token erhalten)...")
    resp = requests.post(f"{SERVER}/api/v1/auth/verify",
                         json={
                             "wallet_address": wallet_address,
                             "signature": signature
                         })
    print(f"    Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        return
    
    data = resp.json()
    token = data["session_token"]
    user = data["user"]
    print(f"    Session Token: {token[:40]}...")
    print(f"    Expires in: {data['expires_in']}s")
    print(f"    User: {user['name']} ({user['id']})")
    print(f"    Wallet: {user['wallet_address']}")
    
    # 5. Authentifizierter Request mit Bearer Token
    print(f"\n[5] Authenticated Request mit Bearer Token...")
    resp = requests.get(f"{SERVER}/api/v1/documents",
                        headers={"Authorization": f"Bearer {token}"})
    print(f"    GET /documents Status: {resp.status_code}")
    if resp.status_code == 200:
        print(f"    ✅ Auth via Session Token funktioniert!")
    else:
        print(f"    ❌ Auth fehlgeschlagen: {resp.text[:100]}")
    
    # 6. Auch noch mit api_key testen (Rückwärtskompatibilität)
    print(f"\n[6] Rückwärtskompatibilität: x-api-key...")
    api_key = hashlib.sha256(PHRASE.encode()).hexdigest()
    resp = requests.get(f"{SERVER}/api/v1/documents",
                        headers={"x-api-key": api_key})
    print(f"    GET /documents Status: {resp.status_code}")
    if resp.status_code == 200:
        print(f"    ✅ x-api-key funktioniert weiterhin!")
    else:
        print(f"    ❌ x-api-key fehlgeschlagen: {resp.text[:100]}")
    
    print(f"\n=== Test abgeschlossen ===")


if __name__ == "__main__":
    main()
