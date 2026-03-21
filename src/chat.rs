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
    /// msg_id der letzten Nachricht
    pub last_msg_id: String,
    /// Wallet des Absenders der letzten Nachricht
    pub last_from_wallet: String,
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
                last_msg_id: last
                    .map(|m| m.msg_id.clone())
                    .unwrap_or_default(),
                last_from_wallet: last
                    .map(|m| m.from_wallet.clone())
                    .unwrap_or_default(),
                unread_count: 0,
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
    ///
    /// Verarbeitet sowohl klassische ChatMessage-TXs als auch Chat-Batch-Nachrichten.
    /// Für Batches wird zuerst der Pool (RAM) geprüft, dann persistierte Batch-Records.
    pub fn rebuild_from_chain(
        blocks: &[&crate::blockchain::Block],
        pool: Option<&crate::message_pool::MessagePool>,
    ) -> Self {
        let mut index = ChatIndex::default();
        let mut batch_count = 0u32;

        for block in blocks {
            // ── Klassische ChatMessage TXs ───────────────────────────────
            for tx in &block.transactions {
                if tx.tx_type != crate::token::TxType::ChatMessage {
                    continue;
                }

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

            // ── Chat-Batch-Nachrichten: Anchor → Pool → BatchRecord ────
            for batch in &block.chat_batches {
                let owned_msgs: Vec<crate::message_pool::PooledMessage>;
                let msgs: &[crate::message_pool::PooledMessage] = if !batch.messages.is_empty() {
                    &batch.messages
                } else if let Some(pool) = pool {
                    let mut v = pool.messages_in_seq_range(batch.seq_start, batch.seq_end);
                    if v.is_empty() {
                        v = pool.load_batch_messages(&batch.merkle_root);
                    }
                    owned_msgs = v;
                    &owned_msgs
                } else {
                    owned_msgs = Vec::new();
                    &owned_msgs
                };

                if !msgs.is_empty() {
                    println!(
                        "[chat-index] Rebuild: Block #{}: {} Batch-Nachrichten (seq {}-{}, root: {}…)",
                        block.index, msgs.len(),
                        batch.seq_start, batch.seq_end,
                        &batch.merkle_root[..12.min(batch.merkle_root.len())],
                    );
                }
                for m in msgs {
                    let key = Self::conv_key(&m.from_wallet, &m.to_wallet);
                    let already = index.conversations.get(&key)
                        .map(|entries| entries.iter().any(|e| e.msg_id == m.msg_id))
                        .unwrap_or(false);
                    if already { continue; }

                    let entry = ChatEntry {
                        msg_id: m.msg_id.clone(),
                        from_wallet: m.from_wallet.clone(),
                        to_wallet: m.to_wallet.clone(),
                        from_user_id: m.from_user_id.clone(),
                        from_name: m.from_name.clone(),
                        encrypted_content: m.encrypted_content.clone(),
                        nonce: m.nonce.clone(),
                        timestamp: m.timestamp,
                        block_index: block.index,
                        tx_id: String::new(),
                    };
                    index.add_message(entry);
                    batch_count += 1;
                }
            }

            index.last_indexed_block = block.index;
        }

        if batch_count > 0 {
            println!("[chat-index] Rebuild: {} Batch-Nachrichten indexiert", batch_count);
        }

        index
    }

    /// Nur neue Blöcke in den Index aufnehmen (inkrementell).
    ///
    /// Verarbeitet sowohl klassische ChatMessage-TXs (backward compat)
    /// als auch Chat-Batch-Nachrichten aus dem MessagePool.
    pub fn index_new_blocks(
        &mut self,
        blocks: &[&crate::blockchain::Block],
        pool: Option<&crate::message_pool::MessagePool>,
    ) {
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

            // ── Chat-Batch-Nachrichten aus dem MessagePool indexieren ──────
            // ── Chat-Batch-Nachrichten: Anchor → Pool → BatchRecord ──────
            for batch in &block.chat_batches {
                let owned_msgs: Vec<crate::message_pool::PooledMessage>;
                let msgs: &[crate::message_pool::PooledMessage] = if !batch.messages.is_empty() {
                    &batch.messages
                } else if let Some(pool) = pool {
                    let mut v = pool.messages_in_seq_range(batch.seq_start, batch.seq_end);
                    if v.is_empty() {
                        v = pool.load_batch_messages(&batch.merkle_root);
                    }
                    owned_msgs = v;
                    &owned_msgs
                } else {
                    owned_msgs = Vec::new();
                    &owned_msgs
                };

                if !msgs.is_empty() {
                    println!(
                        "[chat-index] Block #{}: {} Batch-Nachrichten (seq {}-{}, root: {}…)",
                        block.index, msgs.len(),
                        batch.seq_start, batch.seq_end,
                        &batch.merkle_root[..12.min(batch.merkle_root.len())],
                    );
                }
                for m in msgs {
                    // Duplikat-Check: msg_id bereits im Index?
                    let key = Self::conv_key(&m.from_wallet, &m.to_wallet);
                    let already = self.conversations.get(&key)
                        .map(|entries| entries.iter().any(|e| e.msg_id == m.msg_id))
                        .unwrap_or(false);
                    if already { continue; }

                    let entry = ChatEntry {
                        msg_id: m.msg_id.clone(),
                        from_wallet: m.from_wallet.clone(),
                        to_wallet: m.to_wallet.clone(),
                        from_user_id: m.from_user_id.clone(),
                        from_name: m.from_name.clone(),
                        encrypted_content: m.encrypted_content.clone(),
                        nonce: m.nonce.clone(),
                        timestamp: m.timestamp,
                        block_index: block.index,
                        tx_id: String::new(),
                    };
                    self.add_message(entry);
                    chat_count += 1;
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

// ─── Kontaktliste (Adding-Funktion) ─────────────────────────────────────────

fn contacts_file() -> String {
    format!("{}/contacts.json", data_dir())
}

/// Ein einzelner Kontakt.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Contact {
    /// Wallet-Adresse des Kontakts
    pub wallet: String,
    /// User-ID (falls bekannt)
    pub user_id: String,
    /// Anzeigename (vom User vergeben oder aus Profil)
    pub nickname: String,
    /// Zeitpunkt des Hinzufügens (Unix-Timestamp)
    pub added_at: i64,
}

/// Kontaktliste: Wallet → Vec<Contact>
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ContactList {
    /// Kontakte pro User-Wallet: { "meine_wallet": [Contact, …] }
    pub contacts: HashMap<String, Vec<Contact>>,
}

impl ContactList {
    /// Kontakt hinzufügen. Gibt `false` zurück wenn bereits vorhanden.
    pub fn add_contact(
        &mut self,
        owner_wallet: &str,
        contact_wallet: &str,
        user_id: &str,
        nickname: &str,
    ) -> bool {
        let list = self.contacts.entry(owner_wallet.to_string()).or_default();
        if list.iter().any(|c| c.wallet == contact_wallet) {
            return false; // bereits vorhanden
        }
        list.push(Contact {
            wallet: contact_wallet.to_string(),
            user_id: user_id.to_string(),
            nickname: nickname.to_string(),
            added_at: chrono::Utc::now().timestamp(),
        });
        true
    }

    /// Kontakt entfernen. Gibt `true` zurück wenn entfernt.
    pub fn remove_contact(&mut self, owner_wallet: &str, contact_wallet: &str) -> bool {
        if let Some(list) = self.contacts.get_mut(owner_wallet) {
            let before = list.len();
            list.retain(|c| c.wallet != contact_wallet);
            return list.len() < before;
        }
        false
    }

    /// Kontakte eines Users abrufen.
    pub fn get_contacts(&self, owner_wallet: &str) -> Vec<&Contact> {
        self.contacts
            .get(owner_wallet)
            .map(|list| list.iter().collect())
            .unwrap_or_default()
    }

    /// Prüft ob ein Wallet in den Kontakten ist.
    pub fn is_contact(&self, owner_wallet: &str, contact_wallet: &str) -> bool {
        self.contacts
            .get(owner_wallet)
            .map(|list| list.iter().any(|c| c.wallet == contact_wallet))
            .unwrap_or(false)
    }
}

pub fn load_contacts() -> ContactList {
    if let Ok(data) = fs::read_to_string(contacts_file()) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        ContactList::default()
    }
}

pub fn save_contacts(contacts: &ContactList) {
    if let Ok(json) = serde_json::to_string_pretty(contacts) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(contacts_file(), json);
    }
}

// ─── Kontaktanfragen (Friend Request System) ────────────────────────────────

fn contact_requests_file() -> String {
    format!("{}/contact_requests.json", data_dir())
}

/// Status einer Kontaktanfrage.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ContactRequestStatus {
    Pending,
    Accepted,
    Declined,
}

/// Eine Kontaktanfrage zwischen zwei Usern.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContactRequest {
    /// Eindeutige ID (UUID)
    pub id: String,
    /// Wallet des Absenders
    pub from_wallet: String,
    /// Name des Absenders
    pub from_name: String,
    /// User-ID des Absenders
    pub from_user_id: String,
    /// Wallet des Empfängers
    pub to_wallet: String,
    /// Name des Empfängers
    pub to_name: String,
    /// User-ID des Empfängers
    pub to_user_id: String,
    /// Status
    pub status: ContactRequestStatus,
    /// Erstellt (Unix-Timestamp)
    pub created_at: i64,
    /// Zuletzt aktualisiert (Unix-Timestamp)
    pub updated_at: i64,
}

/// Speicher für alle Kontaktanfragen.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ContactRequestStore {
    pub requests: Vec<ContactRequest>,
}

impl ContactRequestStore {
    /// Neue Anfrage erstellen. Gibt `Err` zurück wenn bereits eine offene existiert.
    pub fn add_request(
        &mut self,
        from_wallet: &str,
        from_name: &str,
        from_user_id: &str,
        to_wallet: &str,
        to_name: &str,
        to_user_id: &str,
    ) -> Result<&ContactRequest, &'static str> {
        // Prüfe ob bereits eine offene Anfrage existiert (in beide Richtungen)
        let exists = self.requests.iter().any(|r| {
            r.status == ContactRequestStatus::Pending
                && ((r.from_wallet == from_wallet && r.to_wallet == to_wallet)
                    || (r.from_wallet == to_wallet && r.to_wallet == from_wallet))
        });
        if exists {
            return Err("Eine offene Anfrage existiert bereits");
        }

        let now = chrono::Utc::now().timestamp();
        let req = ContactRequest {
            id: uuid::Uuid::new_v4().to_string(),
            from_wallet: from_wallet.to_string(),
            from_name: from_name.to_string(),
            from_user_id: from_user_id.to_string(),
            to_wallet: to_wallet.to_string(),
            to_name: to_name.to_string(),
            to_user_id: to_user_id.to_string(),
            status: ContactRequestStatus::Pending,
            created_at: now,
            updated_at: now,
        };
        self.requests.push(req);
        Ok(self.requests.last().unwrap())
    }

    /// Eingehende Anfragen für eine Wallet (status=pending).
    pub fn incoming_for(&self, wallet: &str) -> Vec<&ContactRequest> {
        self.requests
            .iter()
            .filter(|r| r.to_wallet == wallet && r.status == ContactRequestStatus::Pending)
            .collect()
    }

    /// Ausgehende Anfragen einer Wallet (status=pending).
    pub fn outgoing_for(&self, wallet: &str) -> Vec<&ContactRequest> {
        self.requests
            .iter()
            .filter(|r| r.from_wallet == wallet && r.status == ContactRequestStatus::Pending)
            .collect()
    }

    /// Anfrage akzeptieren. Gibt from_wallet und to_wallet zurück (für Auto-Add).
    pub fn accept(&mut self, request_id: &str, wallet: &str) -> Result<(String, String), &'static str> {
        let req = self.requests.iter_mut()
            .find(|r| r.id == request_id && r.to_wallet == wallet && r.status == ContactRequestStatus::Pending)
            .ok_or("Anfrage nicht gefunden oder nicht berechtigt")?;
        req.status = ContactRequestStatus::Accepted;
        req.updated_at = chrono::Utc::now().timestamp();
        Ok((req.from_wallet.clone(), req.to_wallet.clone()))
    }

    /// Anfrage ablehnen.
    pub fn decline(&mut self, request_id: &str, wallet: &str) -> Result<(), &'static str> {
        let req = self.requests.iter_mut()
            .find(|r| r.id == request_id && r.to_wallet == wallet && r.status == ContactRequestStatus::Pending)
            .ok_or("Anfrage nicht gefunden oder nicht berechtigt")?;
        req.status = ContactRequestStatus::Declined;
        req.updated_at = chrono::Utc::now().timestamp();
        Ok(())
    }

    /// Anfrage nach ID finden.
    pub fn find(&self, request_id: &str) -> Option<&ContactRequest> {
        self.requests.iter().find(|r| r.id == request_id)
    }

    /// Alte abgeschlossene Anfragen bereinigen. Behält max `keep` erledigte Einträge.
    pub fn gc_old_requests(&mut self, keep: usize) {
        let (pending, mut done): (Vec<_>, Vec<_>) = self.requests
            .drain(..)
            .partition(|r| r.status == ContactRequestStatus::Pending);
        // Neueste zuerst behalten
        done.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        done.truncate(keep);
        self.requests = pending;
        self.requests.extend(done);
    }
}

pub fn load_contact_requests() -> ContactRequestStore {
    if let Ok(data) = fs::read_to_string(contact_requests_file()) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        ContactRequestStore::default()
    }
}

pub fn save_contact_requests(store: &ContactRequestStore) {
    if let Ok(json) = serde_json::to_string_pretty(store) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(contact_requests_file(), json);
    }
}

// ─── Gruppenchat ─────────────────────────────────────────────────────────────

fn chat_groups_file() -> String {
    format!("{}/chat_groups.json", data_dir())
}

/// Rolle eines Mitglieds in einer Chatgruppe.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GroupRole {
    Admin,
    Member,
}

/// Ein Mitglied einer Chatgruppe.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupMember {
    pub wallet: String,
    pub user_id: String,
    pub name: String,
    pub role: GroupRole,
    pub joined_at: i64,
}

/// Eine Nachricht in einer Chatgruppe.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupChatEntry {
    pub msg_id: String,
    pub group_id: String,
    pub from_wallet: String,
    pub from_user_id: String,
    pub from_name: String,
    pub encrypted_content: String,
    pub nonce: String,
    pub timestamp: i64,
}

/// Eine Chatgruppe mit Mitgliedern und Nachrichten.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatGroup {
    pub id: String,
    pub name: String,
    pub creator_wallet: String,
    pub members: Vec<GroupMember>,
    pub messages: Vec<GroupChatEntry>,
    pub created_at: i64,
}

impl ChatGroup {
    /// Prüft ob eine Wallet Mitglied ist.
    pub fn is_member(&self, wallet: &str) -> bool {
        self.members.iter().any(|m| m.wallet == wallet)
    }

    /// Prüft ob eine Wallet Admin ist.
    pub fn is_admin(&self, wallet: &str) -> bool {
        self.members.iter().any(|m| m.wallet == wallet && m.role == GroupRole::Admin)
    }

    /// Nachricht hinzufügen.
    pub fn add_message(&mut self, entry: GroupChatEntry) {
        self.messages.push(entry);
    }

    /// Mitglied hinzufügen.
    pub fn add_member(&mut self, member: GroupMember) -> Result<(), &'static str> {
        if self.is_member(&member.wallet) {
            return Err("Bereits Mitglied");
        }
        self.members.push(member);
        Ok(())
    }

    /// Mitglied entfernen (nur Admin darf das).
    pub fn remove_member(&mut self, wallet: &str) -> Result<(), &'static str> {
        if wallet == self.creator_wallet {
            return Err("Ersteller kann nicht entfernt werden");
        }
        let before = self.members.len();
        self.members.retain(|m| m.wallet != wallet);
        if self.members.len() == before {
            return Err("Mitglied nicht gefunden");
        }
        Ok(())
    }
}

/// Gruppenchat-Store: Alle Chatgruppen auf dieser Node.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ChatGroupStore {
    pub groups: Vec<ChatGroup>,
}

impl ChatGroupStore {
    /// Gruppe nach ID finden.
    pub fn find(&self, group_id: &str) -> Option<&ChatGroup> {
        self.groups.iter().find(|g| g.id == group_id)
    }

    /// Gruppe nach ID mutable finden.
    pub fn find_mut(&mut self, group_id: &str) -> Option<&mut ChatGroup> {
        self.groups.iter_mut().find(|g| g.id == group_id)
    }

    /// Alle Gruppen für eine Wallet.
    pub fn groups_for(&self, wallet: &str) -> Vec<&ChatGroup> {
        self.groups.iter().filter(|g| g.is_member(wallet)).collect()
    }
}

pub fn load_chat_groups() -> ChatGroupStore {
    if let Ok(data) = fs::read_to_string(chat_groups_file()) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        ChatGroupStore::default()
    }
}

pub fn save_chat_groups(store: &ChatGroupStore) {
    if let Ok(json) = serde_json::to_string_pretty(store) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(chat_groups_file(), json);
    }
}

// ─── Call-Signaling ──────────────────────────────────────────────────────────

fn call_signals_file() -> String {
    format!("{}/call_signals.json", data_dir())
}

/// Typ eines WebRTC-Signaling-Signals.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SignalType {
    Offer,
    Answer,
    IceCandidate,
    Hangup,
    Busy,
    Ringing,
}

/// Ein WebRTC Call-Signal (ephemeral, wird nicht in Blöcke gemined).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CallSignal {
    pub call_id: String,
    pub signal_type: SignalType,
    pub from_wallet: String,
    pub to_wallet: String,
    /// Verschlüsselter SDP/ICE-Payload (AES-256-GCM, base64)
    pub payload: String,
    /// AES-256-GCM Nonce (base64)
    pub nonce: String,
    pub timestamp: i64,
}

/// TTL für Call-Signaling-Nachrichten (60 Sekunden).
const CALL_SIGNAL_TTL_SECS: i64 = 60;

/// Maximale Signale pro Empfänger-Wallet (Anti-Flood).
const MAX_SIGNALS_PER_WALLET: usize = 100;

/// In-Memory Signal-Store: Kurzlebige Signaling-Nachrichten pro Wallet.
///
/// Optimiert für hohe Concurrency (5.000+ gleichzeitige Anrufe):
/// DashMap keyed by to_wallet → O(1) Lookup statt O(n) Scan.
/// Thread-safe ohne externen Mutex.
pub struct CallSignalStore {
    /// Signale gruppiert nach Empfänger-Wallet (lock-free concurrent access)
    signals: dashmap::DashMap<String, Vec<CallSignal>>,
}

impl Default for CallSignalStore {
    fn default() -> Self {
        Self { signals: dashmap::DashMap::new() }
    }
}

impl CallSignalStore {
    /// Signal hinzufügen.
    pub fn add_signal(&self, signal: CallSignal) {
        let mut entry = self.signals
            .entry(signal.to_wallet.clone())
            .or_default();
        // Abgelaufene erst entfernen, dann Limit prüfen
        let now = chrono::Utc::now().timestamp();
        entry.retain(|s| now - s.timestamp < CALL_SIGNAL_TTL_SECS);
        if entry.len() >= MAX_SIGNALS_PER_WALLET {
            return; // Drop — Wallet hat zu viele pending Signale
        }
        entry.push(signal);
    }

    /// Alle Signale für eine Wallet abrufen und gleichzeitig bereinigen (TTL + drain).
    pub fn drain_for(&self, wallet: &str) -> Vec<CallSignal> {
        let now = chrono::Utc::now().timestamp();
        // Wallet-spezifische Signale konsumieren
        if let Some((_, signals)) = self.signals.remove(wallet) {
            signals.into_iter()
                .filter(|s| now - s.timestamp < CALL_SIGNAL_TTL_SECS)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Alle Signale für einen bestimmten Anruf abrufen (read-only).
    pub fn signals_for_call(&self, call_id: &str, wallet: &str) -> Vec<CallSignal> {
        let now = chrono::Utc::now().timestamp();
        self.signals.get(wallet)
            .map(|sigs| sigs.iter()
                .filter(|s| s.call_id == call_id && now - s.timestamp < CALL_SIGNAL_TTL_SECS)
                .cloned()
                .collect())
            .unwrap_or_default()
    }

    /// Garbage-Collection: Abgelaufene Signale entfernen.
    pub fn gc(&self) {
        let now = chrono::Utc::now().timestamp();
        self.signals.retain(|_, sigs| {
            sigs.retain(|s| now - s.timestamp < CALL_SIGNAL_TTL_SECS);
            !sigs.is_empty()
        });
    }
}
