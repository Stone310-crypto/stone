#!/usr/bin/env python3
"""
Test: Complete iOS-like Signup → Challenge-Response Login flow.
This mimics exactly what the iOS app does to find the bug.
"""
import hashlib
import sys
import requests

SERVER = "http://212.227.54.241:8080"

def main():
    print("=== iOS-like Signup + Login Test ===\n")

    # Step 1: Signup (like iOS app does)
    print("[1] POST /auth/signup ...")
    resp = requests.post(f"{SERVER}/api/v1/auth/signup", json={"name": "iOS_Test_User"})
    print(f"    Status: {resp.status_code}")
    if resp.status_code not in (200, 201):
        print(f"    Error: {resp.text}")
        return
    data = resp.json()
    phrase = data.get("phrase")
    server_wallet = data.get("wallet_address", "")
    server_api_key = data.get("api_key", "")
    print(f"    Phrase: {phrase}")
    print(f"    Server wallet_address: {server_wallet}")
    print(f"    Server api_key: {server_api_key[:20]}...")

    if not phrase:
        print("    ERROR: No phrase returned!")
        return

    # Step 2: Derive wallet_address locally (like iOS CryptoHelper.swift does)
    print(f"\n[2] Deriving wallet_address locally from phrase...")
    try:
        from mnemonic import Mnemonic
        m = Mnemonic("english")
        entropy = m.to_entropy(phrase)
    except ImportError:
        print("pip3 install mnemonic")
        sys.exit(1)

    if len(entropy) < 32:
        key_bytes = hashlib.sha256(entropy).digest()
    else:
        key_bytes = bytes(entropy[:32])

    try:
        from nacl.signing import SigningKey
        signing_key = SigningKey(key_bytes)
        local_wallet = signing_key.verify_key.encode().hex()
    except ImportError:
        print("pip3 install PyNaCl")
        sys.exit(1)

    print(f"    Local wallet_address:  {local_wallet}")
    print(f"    Server wallet_address: {server_wallet}")
    print(f"    MATCH: {local_wallet == server_wallet}")

    if local_wallet != server_wallet:
        print("\n    !!! WALLET ADDRESS MISMATCH !!!")
        print("    This is the bug: iOS app derives a different wallet address than the server.")
        return

    # Step 3: Also check phrase hash = api_key
    local_api_key = hashlib.sha256(phrase.encode()).hexdigest()
    print(f"\n[3] Checking api_key derivation...")
    print(f"    Local api_key (SHA256 of phrase):  {local_api_key[:20]}...")
    print(f"    Server api_key:                    {server_api_key[:20]}...")
    print(f"    MATCH: {local_api_key == server_api_key}")

    # Step 4: Challenge-Response Login (like iOS app does after signup)
    print(f"\n[4] POST /auth/challenge ...")
    resp = requests.post(f"{SERVER}/api/v1/auth/challenge",
                         json={"wallet_address": local_wallet})
    print(f"    Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        print("    This is where the iOS app would fail!")
        return
    nonce = resp.json()["challenge"]
    print(f"    Nonce: {nonce[:20]}...")

    # Step 5: Sign nonce
    print(f"\n[5] Signing nonce...")
    signed = signing_key.sign(nonce.encode())
    signature = signed.signature.hex()
    print(f"    Signature: {signature[:40]}...")

    # Step 6: Verify
    print(f"\n[6] POST /auth/verify ...")
    resp = requests.post(f"{SERVER}/api/v1/auth/verify",
                         json={"wallet_address": local_wallet, "signature": signature})
    print(f"    Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        return
    data = resp.json()
    print(f"    Session Token: {data['session_token'][:30]}...")
    print(f"    User: {data['user']['name']} ({data['user']['id']})")

    # Step 7: Authenticated request with session token
    print(f"\n[7] Testing authenticated request with Bearer token...")
    token = data["session_token"]
    resp = requests.get(f"{SERVER}/api/v1/status",
                        headers={"Authorization": f"Bearer {token}"})
    print(f"    Status: {resp.status_code}")
    if resp.status_code == 200:
        print("    Auth with session token works!")
    else:
        print(f"    Error: {resp.text}")

    # Step 8: Also test with api_key
    print(f"\n[8] Testing authenticated request with api_key...")
    resp = requests.get(f"{SERVER}/api/v1/status",
                        headers={"x-api-key": local_api_key})
    print(f"    Status: {resp.status_code}")
    if resp.status_code == 200:
        print("    Auth with api_key works!")
    else:
        print(f"    Error: {resp.text}")

    print("\n=== ALL STEPS PASSED ===")


if __name__ == "__main__":
    main()
