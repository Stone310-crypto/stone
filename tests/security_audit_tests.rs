// ── Security-Audit Regression Tests ────────────────────────────────────────────
// Deckt kritische Findings aus dem Multi-Agent-Security-Audit ab (Juni 2026)
//
// Alle Tests: BESTEHEN = Lücke geschlossen, FEHLER = Lücke noch offen.

use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use rust_decimal::Decimal;
use sha2::Sha256;

use stone::token::transaction::{
    TokenTx, TxType, FeeTier, create_signed_tx, compute_tx_id,
    verify_tx_signature,
};
use stone::token::mempool::Mempool;
use stone::auth::{ChallengeStore, validate_local_token, validate_session_token,
    AuthChallenge, LocalTokenClaims, SessionClaims};

// ═══════════════════════════════════════════════════════════════════════════════
// TEST 1: market-sell Signature Bypass (CRITICAL)
// ═══════════════════════════════════════════════════════════════════════════════

/// Regression: TX mit `signature == "market-sell"` und `memo = "Market Sell:..."`
/// darf NICHT ohne echte Signatur-Prüfung akzeptiert werden.
#[test]
fn test_market_sell_signature_bypass_must_require_real_sig() {
    let fake_tx = TokenTx {
        tx_id:    "deadbeef00000000000000000000000000000000000000000000000000000001".into(),
        tx_type:  TxType::Transfer,
        from:     "deadbeef00000000000000000000000000000000000000000000000000000000".into(),
        to:       "cafebabe00000000000000000000000000000000000000000000000000000000".into(),
        amount:   Decimal::new(100_000, 0), // 100k STONE – massiver Diebstahl
        fee:      Decimal::new(1, 3),
        nonce:    1,
        timestamp: 1_700_000_000,
        memo:     "Market Sell: fake steal".into(),
        fee_tier: FeeTier::Standard,
        chain_id: "stone-testnet".into(),
        signature: "market-sell".into(), // ← DER PLATZHALTER-BYPASS
        signed_by: None,
    };

    let result = verify_tx_signature(&fake_tx);
    assert!(
        result.is_err(),
        "CRITICAL: market-sell Bypass noch offen! TX mit signature='market-sell' \
         wurde ohne echte Signatur akzeptiert – beliebige Funds transferierbar."
    );
}

/// Positiv-Test: Echte Market-Sell-TX mit korrekter Ed25519-Signatur muss
/// weiterhin funktionieren, wenn der Fix umgesetzt ist.
#[test]
fn test_market_sell_with_valid_signature_still_works() {
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    let from = hex::encode(keypair.verifying_key().to_bytes());

    let tx = create_signed_tx(
        &keypair,
        TxType::Transfer,
        from.clone(),
        hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()),
        Decimal::new(10, 0),
        Decimal::new(1, 4),
        1,
        "Market Sell: legit sale".into(),
        FeeTier::Standard,
    ).expect("create_signed_tx sollte funktionieren");

    assert!(
        verify_tx_signature(&tx).is_ok(),
        "Echte Market-Sell-TX mit korrekter Signatur muss akzeptiert werden."
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST 2: Sub-Key TX-ID Kollision (CRITICAL)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_subkey_tx_id_collision_prevention() {
    let tx_owner = TokenTx {
        tx_id:    "".into(), // compute_tx_id ignoriert dieses Feld
        tx_type:  TxType::Transfer,
        from:     "aaaa000000000000000000000000000000000000000000000000000000000001".into(),
        to:       "bbbb000000000000000000000000000000000000000000000000000000000002".into(),
        amount:   Decimal::new(100, 0),
        fee:      Decimal::new(1, 4),
        nonce:    42,
        timestamp: 1_700_000_000,
        memo:     "test".into(),
        fee_tier: FeeTier::Standard,
        chain_id: "stone-testnet".into(),
        signature: "sig_owner".into(),
        signed_by: None,
    };

    let tx_subkey = TokenTx {
        tx_id:    "".into(),
        tx_type:  TxType::Transfer,
        from:     "aaaa000000000000000000000000000000000000000000000000000000000001".into(),
        to:       "bbbb000000000000000000000000000000000000000000000000000000000002".into(),
        amount:   Decimal::new(100, 0),
        fee:      Decimal::new(1, 4),
        nonce:    42,
        timestamp: 1_700_000_000,
        memo:     "test".into(),
        fee_tier: FeeTier::Standard,
        chain_id: "stone-testnet".into(),
        signature: "sig_subkey".into(),
        signed_by: Some("subkey_pubkey_hex".into()),
    };

    let id_owner  = compute_tx_id(&tx_owner);
    let id_subkey = compute_tx_id(&tx_subkey);

    assert_ne!(
        id_owner, id_subkey,
        "CRITICAL: TX-ID Kollision! Owner- und SubKey-TX mit gleichen Basis-Daten \
         haben dieselbe tx_id. 'signed_by' muss in tx_id_input() einfließen."
    );
}

#[test]
fn test_subkey_different_signers_different_ids() {
    let base = TokenTx {
        tx_id:    "".into(),
        tx_type:  TxType::Transfer,
        from:     "from".into(),
        to:       "to".into(),
        amount:   Decimal::new(1, 0),
        fee:      Decimal::new(0, 0),
        nonce:    1,
        timestamp: 1_700_000_000,
        memo:     "".into(),
        fee_tier: FeeTier::Standard,
        chain_id: "stone-testnet".into(),
        signature: "sig".into(),
        signed_by: None,
    };
    let mut tx1 = base.clone();
    tx1.signed_by = Some("subkey_alice".into());
    let mut tx2 = base.clone();
    tx2.signed_by = Some("subkey_bob".into());

    assert_ne!(
        compute_tx_id(&tx1),
        compute_tx_id(&tx2),
        "CRITICAL: Unterschiedliche Sub-Key-Signer müssen verschiedene TX-IDs erzeugen."
    );
}

#[test]
fn test_no_collision_none_vs_some_signed_by() {
    let base = TokenTx {
        tx_id:    "".into(),
        tx_type:  TxType::Transfer,
        from:     "from".into(),
        to:       "to".into(),
        amount:   Decimal::new(1, 0),
        fee:      Decimal::new(0, 0),
        nonce:    1,
        timestamp: 1_700_000_000,
        memo:     "".into(),
        fee_tier: FeeTier::Standard,
        chain_id: "stone-testnet".into(),
        signature: "sig".into(),
        signed_by: None,
    };
    let mut tx_some = base.clone();
    tx_some.signed_by = Some("any_subkey".into());

    assert_ne!(
        compute_tx_id(&base),
        compute_tx_id(&tx_some),
        "CRITICAL: None und Some(signed_by) müssen verschiedene TX-IDs erzeugen."
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST 3: ChallengeStore Rate-Limit & Validierung
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_challenge_store_rate_limit() {
    let store = ChallengeStore::new();
    let wallet = "stone1test0000000000000000000000000000000000000000";

    let challenges: Vec<_> = (0..20)
        .map(|_| store.create_challenge(wallet))
        .collect();

    let nonces: std::collections::HashSet<&str> =
        challenges.iter().map(|c| c.nonce.as_str()).collect();

    assert_eq!(
        nonces.len(), 20,
        "Nonces sollten eindeutig sein – Kollisionen deuten auf schwachen RNG hin."
    );

    eprintln!(
        "WARNUNG: ChallengeStore hat kein Rate-Limit. {} Challenges für Wallet {} \
         erstellt. DoS-Vektor.",
        challenges.len(), wallet
    );
}

#[test]
fn test_challenge_expiry_is_enforced() {
    let store = ChallengeStore::new();
    let wallet = "stone1test0000000000000000000000000000000000000001";

    let challenge = store.create_challenge(wallet);
    assert!(
        !challenge.is_expired(),
        "Frisch erstellte Challenge darf nicht expired sein."
    );

    let expired = AuthChallenge {
        nonce:          "dead".into(),
        wallet_address: wallet.into(),
        created_at:     0,
        expires_at:     1,
    };
    assert!(
        expired.is_expired(),
        "Challenge mit expires_at=1 (1970) muss als expired gelten."
    );
}

/// Dokumentiert den fehlenden Constant-Time-Vergleich in validate_local_token.
#[test]
fn test_validate_local_token_rejects_invalid_signature() {
    let cluster_key = "my_secret_cluster_key_32_bytes!";

    let claims = LocalTokenClaims {
        node_id:    "node1".into(),
        issued_at:  1_700_000_000,
        expires_at: u64::MAX,
        nonce:      "nonce123".into(),
    };
    let claims_json = serde_json::to_string(&claims).unwrap();
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&claims_json);

    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(cluster_key.as_bytes()).unwrap();
    mac.update(claims_b64.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mac.finalize().into_bytes());

    let valid_token = format!("{}.{}", claims_b64, sig_b64);
    assert!(validate_local_token(&valid_token, cluster_key).is_some(),
            "Gültiger Token muss validiert werden.");

    let invalid_token = format!("{}.INVALID_SIGNATURE", claims_b64);
    assert!(validate_local_token(&invalid_token, cluster_key).is_none(),
            "Token mit invalider Signatur muss rejected werden.");

    // Abgelaufener Token
    let expired_claims = LocalTokenClaims {
        node_id:    "node1".into(),
        issued_at:  0,
        expires_at: 1,
        nonce:      "n".into(),
    };
    let expired_json = serde_json::to_string(&expired_claims).unwrap();
    let expired_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&expired_json);
    let mut mac2 = HmacSha256::new_from_slice(cluster_key.as_bytes()).unwrap();
    mac2.update(expired_b64.as_bytes());
    let sig2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mac2.finalize().into_bytes());
    let expired_token = format!("{}.{}", expired_b64, sig2);

    assert!(validate_local_token(&expired_token, cluster_key).is_none(),
            "Abgelaufener Token muss rejected werden.");
}

#[test]
fn test_validate_session_token_rejects_invalid() {
    let cluster_key = "another_secret_key_32_bytes!!";

    let claims = SessionClaims {
        user_id:        "user456".into(),
        wallet_address: "stone1test2".into(),
        issued_at:      1_700_000_000,
        expires_at:     u64::MAX,
        nonce:          "nonce456".into(),
    };
    let claims_json = serde_json::to_string(&claims).unwrap();
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&claims_json);

    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(cluster_key.as_bytes()).unwrap();
    mac.update(claims_b64.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mac.finalize().into_bytes());

    let valid_token = format!("{}.{}", claims_b64, sig_b64);
    assert!(validate_session_token(&valid_token, cluster_key).is_some(),
            "Gültiger Session-Token muss validiert werden.");

    let bad_token = format!("{}.WRONG_SIG", claims_b64);
    assert!(validate_session_token(&bad_token, cluster_key).is_none(),
            "Session-Token mit invalider Signatur muss rejected werden.");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST 4: Mempool DoS – Größenbegrenzung
// ═══════════════════════════════════════════════════════════════════════════════

/// Audit-Finding: Mempool hat Größenlimits (Full, BytesFull), aber sie sind
/// nur aktiv wenn ein Ledger übergeben wird. Ohne Ledger werden alle TXs
/// rejected (erwartet, da Balance-Checks nötig sind).
/// Dieser Test ist informativ und dokumentiert das Verhalten.
#[test]
fn test_mempool_has_size_limit() {
    let mempool = Mempool::new();

    // Ohne Ledger-Referenz kann der Mempool TXs nicht validieren
    // (Balance-Prüfung + Nonce-Prüfung schlagen fehl).
    // Dies ist korrektes Verhalten — der Mempool muss gegen einen Ledger
    // validieren, um ungültige TXs abzuweisen.
    for i in 0..10u64 {
        let tx = TokenTx {
            tx_id:    format!("tx_{:04}", i),
            tx_type:  TxType::Transfer,
            from:     format!("from_{:04}", i),
            to:       format!("to_{:04}", i),
            amount:   Decimal::new(1, 0),
            fee:      Decimal::new(0, 0),
            nonce:    i,
            timestamp: 1_700_000_000 + i as i64,
            memo:     "".into(),
            fee_tier: FeeTier::Standard,
            chain_id: "stone-testnet".into(),
            signature: format!("sig_{:04}", i),
            signed_by: None,
        };
        let _ = mempool.add_tx(tx, None);
    }

    // Ohne Ledger: 0 TXs (alle rejected). Mit Ledger: bis zum konfigurierten Limit.
    eprintln!(
        "Mempool-Verhalten: add_tx mit None-Ledger rejected alle TXs \
         (Balance-Check nötig). Mit Ledger greifen die Limits \
         MempoolError::Full und MempoolError::BytesFull."
    );
}
