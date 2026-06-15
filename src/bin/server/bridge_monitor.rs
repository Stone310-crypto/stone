//! Bridge Payment Monitor
//!
//! Hintergrund-Task der periodisch die Gnosis Safe Transaction Service API
//! pollt um eingehende Zahlungen für Pending Buys zu erkennen.
//!
//! Ablauf:
//! 1. Alle aktiven PendingBuys aus HtlcStore laden
//! 2. Für jede Safe-Adresse die letzten eingehenden Transfers abrufen
//! 3. Matching: Betrag + Asset + Sender prüfen
//! 4. Bei Match: Status → PaymentConfirmed → Auto-Claim auslösen

use std::time::Duration;
use reqwest::Client;
use serde::Deserialize;
use stone::token::htlc::{BuyStatus, PendingBuy, HTLC_ESCROW_POOL};
use stone::token::{TokenTx, TxType, FeeTier, HtlcClaimParams, default_chain_id, compute_tx_id};
use super::state::AppState;
use super::handlers::token::load_bridge_safes_config;

/// Polling-Intervall für den Bridge Monitor.
const POLL_INTERVAL_SECS: u64 = 30;

/// Startet den Bridge Monitor als Hintergrund-Task.
pub fn start_bridge_monitor(state: AppState) {
    tokio::spawn(async move {
        // Erst nach 15s starten (Server soll erst vollständig hochfahren)
        tokio::time::sleep(Duration::from_secs(15)).await;
        println!("[bridge-monitor] 🔍 Bridge Payment Monitor gestartet (Intervall: {POLL_INTERVAL_SECS}s)");

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("HTTP client");

        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));

        loop {
            interval.tick().await;

            // 1. Abgelaufene Buys expiren
            {
                let now = chrono::Utc::now().timestamp();
                let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
                let expired = store.expire_pending_buys(now);
                if !expired.is_empty() {
                    println!("[bridge-monitor] ⏰ {} Pending Buys abgelaufen", expired.len());
                    let _ = store.persist();
                }
                // Alte Einträge aufräumen (nach 24h)
                store.cleanup_pending_buys(86400, now);
            }

            // 2. Aktive Pending Buys sammeln
            let active_buys: Vec<PendingBuy> = {
                let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
                store.active_pending_buys().into_iter().cloned().collect()
            };

            if active_buys.is_empty() {
                continue;
            }

            // 3. Safe-Config laden
            let safes_config = load_bridge_safes_config();

            // 4. Für jede Chain prüfen ob es relevante Buys gibt
            for buy in &active_buys {
                let chain_config = match safes_config.get(&buy.expected_chain) {
                    Some(cfg) => cfg,
                    None => continue,
                };
                let safe_addr = match chain_config.get("safe_address").and_then(|v| v.as_str()) {
                    Some(a) if !a.is_empty() => a,
                    _ => continue,
                };
                let safe_api = match chain_config.get("safe_api").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => continue,
                };

                // Token-Contract-Adresse für das erwartete Asset finden
                let token_contract = chain_config
                    .get("tokens")
                    .and_then(|v| v.as_object())
                    .and_then(|tokens| tokens.get(&buy.expected_asset))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Safe Transaction Service API abrufen
                match check_safe_transfers(&client, safe_api, safe_addr, token_contract, buy).await {
                    Ok(Some(tx_hash)) => {
                        println!(
                            "[bridge-monitor] ✅ Zahlung erkannt für Buy {} (HTLC {}): tx={}",
                            buy.buy_id, buy.htlc_id, tx_hash
                        );
                        // Status aktualisieren
                        {
                            let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
                            store.set_pending_buy_payment_tx(&buy.buy_id, tx_hash);
                            store.update_pending_buy_status(&buy.buy_id, BuyStatus::PaymentConfirmed);
                            let _ = store.persist();
                        }
                        // Auto-Claim auslösen
                        execute_auto_claim(&state, buy).await;
                    }
                    Ok(None) => {
                        // Noch keine Zahlung gefunden
                    }
                    Err(e) => {
                        eprintln!("[bridge-monitor] ⚠️  API-Fehler für {} ({}): {e}", buy.expected_chain, safe_addr);
                    }
                }
            }
        }
    });
}

// ─── Safe Transaction Service API ────────────────────────────────────────────

/// Antwort-Struktur des Gnosis Safe Transaction Service `/transfers/` Endpoints.
#[derive(Deserialize, Debug)]
struct SafeTransferPage {
    results: Vec<SafeTransfer>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SafeTransfer {
    transfer_type: Option<String>,
    transaction_hash: Option<String>,
    #[allow(dead_code)]
    from: Option<String>,
    to: Option<String>,
    value: Option<String>,
    token_info: Option<TokenInfoResp>,
    execution_date: Option<String>,
}

#[derive(Deserialize, Debug)]
struct TokenInfoResp {
    address: Option<String>,
    #[allow(dead_code)]
    symbol: Option<String>,
    decimals: Option<u32>,
}

/// Prüft den Safe Transaction Service auf eingehende Transfers die zu einem PendingBuy passen.
async fn check_safe_transfers(
    client: &Client,
    safe_api: &str,
    safe_address: &str,
    token_contract: &str,
    buy: &PendingBuy,
) -> Result<Option<String>, String> {
    // URL: GET /api/v1/safes/{address}/incoming-transfers/?limit=20
    let url = format!(
        "https://{}/api/v1/safes/{}/incoming-transfers/?limit=20&executed=true",
        safe_api, safe_address
    );

    let resp = client.get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let page: SafeTransferPage = resp.json().await
        .map_err(|e| format!("JSON parse failed: {e}"))?;

    // Überpüfen ob ein Transfer dem PendingBuy entspricht
    let buy_created_at = buy.created_at;

    for transfer in &page.results {
        // Nur eingehende Transfers (to == safe_address)
        let to_addr = transfer.to.as_deref().unwrap_or("");
        if !to_addr.eq_ignore_ascii_case(safe_address) {
            continue;
        }

        // Nur Transfers nach dem Buy-Zeitpunkt
        if let Some(ref exec_date) = transfer.execution_date {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exec_date) {
                if dt.timestamp() < buy_created_at {
                    continue;
                }
            }
        }

        // ERC20: Token-Contract prüfen
        if let Some(ref info) = transfer.token_info {
            let contract_addr = info.address.as_deref().unwrap_or("");
            if !token_contract.is_empty() && !contract_addr.eq_ignore_ascii_case(token_contract) {
                continue;
            }

            // Betrag prüfen (mit Decimals)
            let decimals = info.decimals.unwrap_or(18);
            let raw_value = transfer.value.as_deref().unwrap_or("0");
            if check_amount_match(raw_value, &buy.expected_amount, decimals) {
                return Ok(transfer.transaction_hash.clone());
            }
        } else if buy.expected_asset == "ETH" {
            // Native ETH Transfer
            let raw_value = transfer.value.as_deref().unwrap_or("0");
            if check_amount_match(raw_value, &buy.expected_amount, 18) {
                return Ok(transfer.transaction_hash.clone());
            }
        }
    }

    Ok(None)
}

/// Prüft ob der rohe Wert (in kleinster Einheit) dem erwarteten Betrag entspricht.
/// Toleranz: ±1% um Rundungsfehler und Gas-Abzüge zu kompensieren.
fn check_amount_match(raw_value: &str, expected_amount: &str, decimals: u32) -> bool {
    let raw: f64 = raw_value.parse().unwrap_or(0.0);
    let expected: f64 = expected_amount.parse().unwrap_or(0.0);
    if expected <= 0.0 {
        return false;
    }

    let divisor = 10f64.powi(decimals as i32);
    let actual_amount = raw / divisor;

    // ±1% Toleranz
    let ratio = actual_amount / expected;
    (0.99..=1.01).contains(&ratio)
}

// ─── Auto-Claim ──────────────────────────────────────────────────────────────

/// Führt den Auto-Claim für einen bestätigten PendingBuy aus.
async fn execute_auto_claim(state: &AppState, buy: &PendingBuy) {
    // Preimage aus Escrow holen
    let preimage = {
        let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
        store.get_escrowed_preimage(&buy.htlc_id).cloned()
    };

    let preimage = match preimage {
        Some(p) => p,
        None => {
            eprintln!("[bridge-monitor] ❌ Kein Preimage für HTLC {} – manueller Claim nötig", buy.htlc_id);
            let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
            store.update_pending_buy_status(
                &buy.buy_id,
                BuyStatus::Failed("Kein Preimage verfügbar".to_string()),
            );
            let _ = store.persist();
            return;
        }
    };

    // Claim-TX bauen (gleiche Logik wie handle_htlc_buy)
    let now = chrono::Utc::now().timestamp();
    let memo = serde_json::to_string(&HtlcClaimParams {
        htlc_id: buy.htlc_id.clone(),
        preimage: preimage.clone(),
    }).unwrap_or_default();

    let mut tx = TokenTx {
        tx_id: String::new(),
        tx_type: TxType::HtlcClaim,
        from: HTLC_ESCROW_POOL.to_string(),
        to: buy.buyer.clone(),
        amount: {
            let store = state.node.htlc_store.read().unwrap_or_else(|e| e.into_inner());
            match store.get(&buy.htlc_id) {
                Some(c) => c.amount,
                None => {
                    eprintln!("[bridge-monitor] ❌ HTLC {} nicht gefunden", buy.htlc_id);
                    return;
                }
            }
        },
        fee: rust_decimal::Decimal::ZERO,
        nonce: 0,
        timestamp: now,
        signature: "system".to_string(),
        memo,
        chain_id: default_chain_id(),
        fee_tier: FeeTier::Standard,
        signed_by: None,
    };
    tx.tx_id = compute_tx_id(&tx);
    let tx_id = tx.tx_id.clone();

    let result = {
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        state.node.mempool.add_tx(tx.clone(), Some(&ledger))
    };

    match result {
        Ok(()) => {
            println!(
                "[bridge-monitor] ✅ Auto-Claim erfolgreich: Buy {} → TX {}",
                buy.buy_id, tx_id
            );
            {
                let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
                store.remove_escrowed_preimage(&buy.htlc_id);
                store.set_pending_buy_claim_tx(&buy.buy_id, tx_id.clone());
                store.update_pending_buy_status(&buy.buy_id, BuyStatus::Completed);
                let _ = store.persist();
            }

            // TX broadcasten
            if let Some(ref net) = state.network {
                let net = net.clone();
                tokio::spawn(async move { net.broadcast_tx(tx).await; });
            }
        }
        Err(e) => {
            eprintln!("[bridge-monitor] ❌ Claim fehlgeschlagen für Buy {}: {e}", buy.buy_id);
            let mut store = state.node.htlc_store.write().unwrap_or_else(|e| e.into_inner());
            store.update_pending_buy_status(
                &buy.buy_id,
                BuyStatus::Failed(format!("Mempool: {e}")),
            );
            let _ = store.persist();
        }
    }
}
