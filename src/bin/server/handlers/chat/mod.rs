//! Chat handler module — aufgeteilt in fokussierte Sub-Module.
//!
//! Verschlüsselte P2P-Nachrichten, Kontakte, Friend Requests,
//! Coin-Transfers im Chat, Merkle-Proofs und System-Nachrichten.

use serde::Deserialize;
use serde_json::json;

use crate::server::state::AppState;

mod messages;
mod contacts;
mod requests;
mod coins;
mod resolve;
mod proof;
mod system;

pub use messages::*;
pub use contacts::*;
pub use requests::*;
pub use coins::*;
pub use resolve::*;
pub use proof::*;
pub use system::*;

// ─── Gemeinsame Request-Typen ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendChatRequest {
    /// Mnemonic (BIP39) des Senders – wird NICHT gespeichert
    #[serde(default)]
    pub mnemonic: String,
    /// Empfänger: Wallet-Adresse (64 Hex) oder User-ID (UUID)
    #[serde(default)]
    pub to: String,
    /// AES-256-GCM verschlüsselter Nachrichteninhalt (base64)
    #[serde(default)]
    pub encrypted_content: String,
    /// AES-256-GCM Nonce (base64, 12 Bytes)
    #[serde(default)]
    pub nonce: String,
    /// Nachrichten-TTL: "30" (30 Tage) oder "90" (90 Tage). Default: 30
    #[serde(default)]
    pub ttl: Option<String>,
}

#[derive(Deserialize)]
pub struct MessagesQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

// ─── Gemeinsame Hilfsfunktionen ───────────────────────────────────────────────

/// User-ID oder Wallet-Adresse zu Wallet auflösen
pub(super) fn resolve_recipient(identifier: &str, state: &AppState) -> Option<String> {
    // System-Adressen (z.B. system:stoneteam)
    if identifier.starts_with("system:") {
        return Some(identifier.to_string());
    }

    // Direkte Wallet-Adresse (64 Hex)
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(identifier.to_string());
    }

    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());

    // User-ID (UUID)
    if let Some(u) = users.iter().find(|u| u.id == identifier) {
        if !u.wallet_address.is_empty() {
            return Some(u.wallet_address.clone());
        }
    }

    // Name (exakter Match, case-insensitive)
    let lower = identifier.to_lowercase();
    users
        .iter()
        .find(|u| u.name.to_lowercase() == lower && !u.wallet_address.is_empty())
        .map(|u| u.wallet_address.clone())
}

/// Neue Blöcke in den Chat-Index laden (inkrementell)
///
/// Erkennt auch Chain-Resets: wenn `last_indexed_block > chain_len`,
/// wird der Index komplett neu aufgebaut.
pub(super) fn index_new_blocks_if_needed(state: &AppState) {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());

    let chain_len = chain.blocks.len() as u64;
    let last_idx = idx.last_indexed_block;
    let last_chain_block_idx = chain.blocks.last().map(|b| b.index).unwrap_or(0);

    // ── Chain-Reset erkennen ──────────────────────────────────────────────
    if last_idx > 0 && chain_len > 0 && last_idx > last_chain_block_idx {
        println!(
            "[chat-index] ⚠️ Chain-Reset erkannt! last_indexed_block={} aber letzter Block ist #{}. Rebuild...",
            last_idx, last_chain_block_idx
        );
        let old_content: std::collections::HashMap<String, (String, String)> = idx.conversations.values()
            .flat_map(|entries| entries.iter())
            .filter(|e| !e.encrypted_content.is_empty())
            .map(|e| (e.msg_id.clone(), (e.encrypted_content.clone(), e.nonce.clone())))
            .collect();

        let all_blocks: Vec<_> = chain.blocks.iter().collect();
        *idx = stone::chat::ChatIndex::rebuild_from_chain(&all_blocks, Some(&state.node.message_pool));

        if !old_content.is_empty() {
            for entries in idx.conversations.values_mut() {
                for entry in entries.iter_mut() {
                    if entry.encrypted_content.is_empty() {
                        if let Some((enc, nc)) = old_content.get(&entry.msg_id) {
                            entry.encrypted_content = enc.clone();
                            entry.nonce = nc.clone();
                        }
                    }
                }
            }
        }

        let _ = stone::chat::save_chat_index(&idx);
        println!(
            "[chat-index] ✅ Rebuild fertig: {} Konversationen, last_indexed_block={}",
            idx.conversations.len(),
            idx.last_indexed_block,
        );
        return;
    }

    // ── Inkrementelles Indexieren ─────────────────────────────────────────
    if chain_len > 0 && last_chain_block_idx > last_idx {
        let new_blocks: Vec<_> = chain
            .blocks
            .iter()
            .filter(|b| b.index > last_idx)
            .collect();

        if !new_blocks.is_empty() {
            println!(
                "[chat-index] 📋 {} neue Blöcke indexieren (ab Block #{})",
                new_blocks.len(),
                last_idx + 1,
            );
            idx.index_new_blocks(&new_blocks, Some(&state.node.message_pool));
            let _ = stone::chat::save_chat_index(&idx);
        }
    }

    // ── Self-Destruct GC: Abgelaufene Nachrichten-Content löschen ─────────
    {
        let mut policy = state.node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
        let purged = stone::chat_policy::gc_expired_messages(&mut policy, &mut idx);
        if purged > 0 {
            let _ = stone::chat::save_chat_index(&idx);
            let _ = policy.persist();
        }
    }
}

/// Lokale Suche: state.users + on-chain account_names.
pub(super) fn resolve_local(identifier: &str, state: &AppState) -> Vec<serde_json::Value> {
    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());

    // 1) Exakte User-ID
    if let Some(u) = users.iter().find(|u| u.id == identifier) {
        if !u.wallet_address.is_empty() {
            return vec![json!({
                "user_id": u.id,
                "name": u.name,
                "wallet": u.wallet_address,
            })];
        }
    }

    // 2) Wallet-Adresse direkt
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(u) = users.iter().find(|u| u.wallet_address == identifier) {
            return vec![json!({
                "user_id": u.id,
                "name": u.name,
                "wallet": u.wallet_address,
            })];
        }
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        if ledger.all_registered_accounts().contains_key(identifier) {
            return vec![json!({
                "user_id": "",
                "name": "Unbekannt",
                "wallet": identifier,
            })];
        }
    }

    // 3) Name-Suche (case-insensitive, substring) — lokale Users
    let lower = identifier.to_lowercase();
    let mut matches: Vec<serde_json::Value> = users
        .iter()
        .filter(|u| !u.wallet_address.is_empty() && u.name.to_lowercase().contains(&lower))
        .map(|u| {
            json!({
                "user_id": u.id,
                "name": u.name,
                "wallet": u.wallet_address,
            })
        })
        .collect();

    // 4) On-Chain Account-Registry (andere Nodes)
    {
        let known_wallets: std::collections::HashSet<String> = matches
            .iter()
            .filter_map(|m| m["wallet"].as_str().map(|s| s.to_string()))
            .collect();
        let ledger = state.node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
        for (wallet, name) in ledger.all_registered_accounts() {
            if known_wallets.contains(wallet) {
                continue;
            }
            if name.to_lowercase().contains(&lower) {
                let user_id = users.iter()
                    .find(|u| u.wallet_address == *wallet)
                    .map(|u| u.id.clone())
                    .unwrap_or_default();
                matches.push(json!({
                    "user_id": user_id,
                    "name": name,
                    "wallet": wallet,
                }));
            }
        }
    }

    matches
}

/// Peer-Nodes nach einem User fragen (parallel, Timeout 3s).
pub(super) async fn resolve_from_peers(identifier: &str, state: &AppState) -> Vec<serde_json::Value> {
    let peers = state.node.get_peers();
    if peers.is_empty() {
        return vec![];
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut handles = Vec::new();
    for peer in &peers {
        let sync_url = crate::server::sync::to_sync_url(&peer.url);
        let url = format!(
            "{}/resolve/{}",
            sync_url,
            identifier
        );
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            match c.get(&url).send().await {
                Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.ok(),
                _ => None,
            }
        }));
    }

    let mut all: Vec<serde_json::Value> = Vec::new();
    let mut seen_wallets: std::collections::HashSet<String> = std::collections::HashSet::new();
    for h in handles {
        if let Ok(Some(body)) = h.await {
            if let Some(results) = body.get("results").and_then(|v| v.as_array()) {
                for r in results {
                    let w = r["wallet"].as_str().unwrap_or_default().to_string();
                    if !w.is_empty() && seen_wallets.insert(w) {
                        all.push(r.clone());
                    }
                }
            }
        }
    }
    all
}
