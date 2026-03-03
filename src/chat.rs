//! Globaler verschlüsselter Chat auf der StoneChain.
//!
//! Jeder User kann jedem anderen User (über User-ID → Wallet-Adresse) eine
//! verschlüsselte Nachricht senden. Die Nachrichten werden als `ChatMessage`-TXs
//! in die Blockchain geschrieben und damit durch Mining validiert.
//!
//! ## Verschlüsselung
//!
//! Die Nachrichten sind AES-256-GCM verschlüsselt. Der Shared Secret wird
//! über ECDH aus den Wallet-Keys beider Parteien abgeleitet.
//! Nur Sender und Empfänger können die Nachrichten lesen.
//!
//! ## Lokaler Index
//!
//! Für schnellen Zugriff wird ein lokaler Chat-Index in `stone_data/chat_index.json`
//! zwischengespeichert. Dieser wird beim Start aus der Blockchain rekonstruiert.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use crate::blockchain::data_dir;

fn chat_index_file() -> String {
    format!("{}/chat_index.json", data_dir())
}

// ─── Chat-Nachricht (Index-Eintrag) ──────────────────────────────────────────

/// Ein Chat-Nachrichten-Eintrag (aus der Blockchain extrahiert).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatEntry {
    /// Eindeutige Nachrichten-ID
    pub msg_id: String,
    /// Sender Wallet-Adresse
    pub from_wallet: String,
    /// Empfänger Wallet-Adresse
    pub to_wallet: String,
    /// Sender User-ID (für Anzeige)
    pub from_user_id: String,
    /// Sender Display-Name
    pub from_name: String,
    /// AES-256-GCM verschlüsselter Inhalt (base64)
    pub encrypted_content: String,
    /// AES-256-GCM Nonce (base64, 12 Bytes)
    pub nonce: String,
    /// Unix-Timestamp
    pub timestamp: i64,
    /// Block-Index in dem die Nachricht geminet wurde (0 = pending)
    pub block_index: u64,
    /// TX-ID in der Blockchain
    pub tx_id: String,
}

// ─── Konversation (zwischen zwei Usern) ──────────────────────────────────────

/// Zusammenfassung einer Konversation für die Übersicht.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConversationSummary {
    /// Wallet-Adresse des anderen Teilnehmers
    pub peer_wallet: String,
    /// User-ID des anderen Teilnehmers
    pub peer_user_id: String,
    /// Display-Name des anderen Teilnehmers
    pub peer_name: String,
    /// Letzte Nachricht (verschlüsselt)
    pub last_message_preview: String,
    /// Timestamp der letzten Nachricht
    pub last_timestamp: i64,
    /// Anzahl ungelesener Nachrichten
    pub unread_count: u32,
    /// Gesamtzahl der Nachrichten
    pub total_messages: u32,
}

// ─── Chat-Index ──────────────────────────────────────────────────────────────

/// Lokaler Chat-Index: Wallet → [ChatEntry]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ChatIndex {
    /// Alle Chat-Nachrichten, gruppiert nach Konversations-Key.
    /// Key = sortierte Wallet-Adressen ("walletA:walletB") → Messages
    pub conversations: HashMap<String, Vec<ChatEntry>>,
    /// Letzter verarbeiteter Block-Index
    pub last_indexed_block: u64,
}

impl ChatIndex {
    /// Konversations-Key: sortierte Wallet-Adressen (deterministic)
    pub fn conv_key(wallet_a: &str, wallet_b: &str) -> String {
        let mut pair = [wallet_a, wallet_b];
        pair.sort();
        format!("{}:{}", pair[0], pair[1])
    }

    /// Nachricht hinzufügen
    pub fn add_message(&mut self, entry: ChatEntry) {
        let key = Self::conv_key(&entry.from_wallet, &entry.to_wallet);
        self.conversations.entry(key).or_default().push(entry);
    }

    /// Alle Konversationen für eine Wallet-Adresse abrufen.
    pub fn conversations_for(&self, wallet: &str, users: &[crate::auth::User]) -> Vec<ConversationSummary> {
        let mut result: Vec<ConversationSummary> = Vec::new();

        for (key, messages) in &self.conversations {
            // Prüfe ob diese Wallet an der Konversation beteiligt ist
            let parts: Vec<&str> = key.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }
            let (a, b) = (parts[0], parts[1]);
            if a != wallet && b != wallet {
                continue;
            }
            let peer_wallet = if a == wallet { b } else { a };

            // Peer-Info auflösen
            let (peer_user_id, peer_name) = users
                .iter()
                .find(|u| u.wallet_address == peer_wallet)
                .map(|u| (u.id.clone(), u.name.clone()))
                .unwrap_or_else(|| (String::new(), format!("{}…", &peer_wallet[..8.min(peer_wallet.len())])));

            let last = messages.last();
            result.push(ConversationSummary {
                peer_wallet: peer_wallet.to_string(),
                peer_user_id,
                peer_name,
                last_message_preview: last
                    .map(|m| m.encrypted_content.clone())
                    .unwrap_or_default(),
                last_timestamp: last.map(|m| m.timestamp).unwrap_or(0),
                unread_count: 0, // Client verwaltet "gelesen" Status lokal
                total_messages: messages.len() as u32,
            });
        }

        // Nach letzter Nachricht sortieren (neueste zuerst)
        result.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));
        result
    }

    /// Chat-Verlauf zwischen zwei Wallets (neueste zuletzt), mit Pagination.
    pub fn messages_between(&self, wallet_a: &str, wallet_b: &str, limit: usize, offset: usize) -> Vec<&ChatEntry> {
        let key = Self::conv_key(wallet_a, wallet_b);
        let Some(msgs) = self.conversations.get(&key) else {
            return Vec::new();
        };
        // Offset von hinten (neueste zuerst als Basis, dann Slice)
        let end = if msgs.len() > offset {
            msgs.len() - offset
        } else {
            return Vec::new();
        };
        let start = if end > limit { end - limit } else { 0 };
        msgs[start..end].iter().collect()
    }

    /// Index aus der Blockchain rekonstruieren.
    pub fn rebuild_from_chain(blocks: &[&crate::blockchain::Block]) -> Self {
        let mut index = ChatIndex::default();

        for block in blocks {
            for tx in &block.transactions {
                if tx.tx_type != crate::token::TxType::ChatMessage {
                    continue;
                }

                // Memo enthält JSON: {"msg_id":"…","encrypted":"…","nonce":"…","from_user_id":"…","from_name":"…"}
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&tx.memo) {
                    let entry = ChatEntry {
                        msg_id: data["msg_id"].as_str().unwrap_or("").to_string(),
                        from_wallet: tx.from.clone(),
                        to_wallet: tx.to.clone(),
                        from_user_id: data["from_user_id"].as_str().unwrap_or("").to_string(),
                        from_name: data["from_name"].as_str().unwrap_or("").to_string(),
                        encrypted_content: data["encrypted"].as_str().unwrap_or("").to_string(),
                        nonce: data["nonce"].as_str().unwrap_or("").to_string(),
                        timestamp: tx.timestamp,
                        block_index: block.index,
                        tx_id: tx.tx_id.clone(),
                    };
                    index.add_message(entry);
                }
            }
            index.last_indexed_block = block.index;
        }

        index
    }

    /// Nur neue Blöcke in den Index aufnehmen (inkrementell).
    pub fn index_new_blocks(&mut self, blocks: &[&crate::blockchain::Block]) {
        let mut chat_count = 0u32;
        for block in blocks {
            if block.index <= self.last_indexed_block {
                continue;
            }
            let tx_count = block.transactions.len();
            let chat_txs: Vec<_> = block.transactions.iter()
                .filter(|tx| tx.tx_type == crate::token::TxType::ChatMessage)
                .collect();
            if !chat_txs.is_empty() {
                println!(
                    "[chat-index] Block #{}: {} ChatMessage TXs gefunden (von {} TXs gesamt)",
                    block.index, chat_txs.len(), tx_count
                );
            }
            for tx in &chat_txs {
                match serde_json::from_str::<serde_json::Value>(&tx.memo) {
                    Ok(data) => {
                        let entry = ChatEntry {
                            msg_id: data["msg_id"].as_str().unwrap_or("").to_string(),
                            from_wallet: tx.from.clone(),
                            to_wallet: tx.to.clone(),
                            from_user_id: data["from_user_id"].as_str().unwrap_or("").to_string(),
                            from_name: data["from_name"].as_str().unwrap_or("").to_string(),
                            encrypted_content: data["encrypted"].as_str().unwrap_or("").to_string(),
                            nonce: data["nonce"].as_str().unwrap_or("").to_string(),
                            timestamp: tx.timestamp,
                            block_index: block.index,
                            tx_id: tx.tx_id.clone(),
                        };
                        println!(
                            "[chat-index] ✅ ChatMessage indexiert: {} → {} (msg_id: {}, block: #{})",
                            &tx.from[..12.min(tx.from.len())],
                            &tx.to[..12.min(tx.to.len())],
                            &entry.msg_id[..8.min(entry.msg_id.len())],
                            block.index,
                        );
                        self.add_message(entry);
                        chat_count += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            "[chat-index] ⚠️ Memo-Parse fehlgeschlagen für TX {} in Block #{}: {e} — Memo: {}",
                            &tx.tx_id[..12.min(tx.tx_id.len())],
                            block.index,
                            &tx.memo[..80.min(tx.memo.len())],
                        );
                    }
                }
            }
            self.last_indexed_block = block.index;
        }
        if chat_count > 0 {
            println!("[chat-index] 📬 {} neue Chat-Nachrichten indexiert, last_indexed_block = {}", chat_count, self.last_indexed_block);
        }
    }
}

// ─── Persistenz ──────────────────────────────────────────────────────────────

pub fn load_chat_index() -> ChatIndex {
    if let Ok(data) = fs::read_to_string(chat_index_file()) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        ChatIndex::default()
    }
}

pub fn save_chat_index(index: &ChatIndex) {
    if let Ok(json) = serde_json::to_string(index) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(chat_index_file(), json);
    }
}
