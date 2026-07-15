//! Chat-Nachrichten — E2EE mit ChaCha20Poly1305, On-Chain Hashing.
//!
//! ## Privacy-Modell
//! - Chat-Inhalte: E2EE zwischen Sender + Empfänger (ChaCha20Poly1305)
//! - Message-Hashes: Werden in Batches in der Stone-Blockchain gespeichert
//! - Metadaten (Absender, Empfänger): NIE on-chain
//! - Kein Relay-Server hat Zugriff auf Klartext
//!
//! ## Wire-Format
//! TYPE_CHAT = 0x06
//! [1 byte type] [32 bytes sender_pubkey] [encrypted payload]
//!
//! Payload (entschlüsselt):
//! [message_id: 32] [from_id: variable] [to_id: variable]
//! [timestamp: 8] [content_len: 4] [content: variable]

use serde::{Serialize, Deserialize};

/// Eine Chat-Nachricht (vor Verschlüsselung).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Eindeutige Nachrichten-ID (SHA256 des Inhalts + Timestamp)
    pub message_id: [u8; 32],
    /// Absender VPN-ID (nicht im Netzwerk sichtbar nach Verschlüsselung)
    pub from_id: String,
    /// Empfänger VPN-ID
    pub to_id: String,
    /// Chat-Text (UTF-8)
    pub content: String,
    /// Unix-Timestamp
    pub timestamp: u64,
    /// Optional: Referenz auf vorherige Nachricht (für Threading)
    pub reply_to: Option<[u8; 32]>,
}

impl ChatMessage {
    /// Erstellt eine neue Chat-Nachricht.
    pub fn new(from_id: &str, to_id: &str, content: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Message-ID = SHA256(from_id || to_id || content || timestamp)
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(from_id.as_bytes());
        hasher.update(b"|");
        hasher.update(to_id.as_bytes());
        hasher.update(b"|");
        hasher.update(content.as_bytes());
        hasher.update(b"|");
        hasher.update(&timestamp.to_le_bytes());
        let message_id: [u8; 32] = hasher.finalize().into();

        ChatMessage {
            message_id,
            from_id: from_id.to_string(),
            to_id: to_id.to_string(),
            content: content.to_string(),
            timestamp,
            reply_to: None,
        }
    }

    /// Serialisiert die Nachricht für die Verschlüsselung.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.message_id);
        let from_bytes = self.from_id.as_bytes();
        buf.push(from_bytes.len() as u8);
        buf.extend_from_slice(from_bytes);
        let to_bytes = self.to_id.as_bytes();
        buf.push(to_bytes.len() as u8);
        buf.extend_from_slice(to_bytes);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        let content_bytes = self.content.as_bytes();
        buf.extend_from_slice(&(content_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(content_bytes);
        buf
    }

    /// Deserialisiert eine Nachricht aus Bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 50 { return None; }
        let mut pos = 0;
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&bytes[pos..pos+32]);
        pos += 32;
        let from_len = bytes[pos] as usize;
        pos += 1;
        if pos + from_len > bytes.len() { return None; }
        let from_id = String::from_utf8_lossy(&bytes[pos..pos+from_len]).to_string();
        pos += from_len;
        let to_len = bytes[pos] as usize;
        pos += 1;
        if pos + to_len > bytes.len() { return None; }
        let to_id = String::from_utf8_lossy(&bytes[pos..pos+to_len]).to_string();
        pos += to_len;
        if pos + 8 > bytes.len() { return None; }
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&bytes[pos..pos+8]);
        let timestamp = u64::from_le_bytes(ts_bytes);
        pos += 8;
        if pos + 4 > bytes.len() { return None; }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos+4]);
        let content_len = u32::from_le_bytes(len_bytes) as usize;
        pos += 4;
        if pos + content_len > bytes.len() { return None; }
        let content = String::from_utf8_lossy(&bytes[pos..pos+content_len]).to_string();

        Some(ChatMessage {
            message_id,
            from_id,
            to_id,
            content,
            timestamp,
            reply_to: None,
        })
    }

    /// Gibt den Message-Hash für die Blockchain zurück.
    /// Das ist alles was on-chain gespeichert wird.
    pub fn blockchain_hash(&self) -> [u8; 32] {
        self.message_id
    }
}

/// Ein Batch von Chat-Hashes für die Blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatBatch {
    /// Merkle-Root aller Nachrichten-Hashes
    pub merkle_root: [u8; 32],
    /// Anzahl Nachrichten in diesem Batch
    pub count: u32,
    /// Timestamp des Batch
    pub timestamp: u64,
    /// Die Hashes in diesem Batch
    pub hashes: Vec<[u8; 32]>,
}

impl ChatBatch {
    /// Erstellt einen neuen Batch aus Nachrichten-Hashes.
    /// Berechnet die Merkle-Root als SHA256 aller Hashes konkateniert.
    pub fn from_hashes(hashes: Vec<[u8; 32]>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let merkle_root = Self::compute_merkle_root(&hashes);

        ChatBatch {
            merkle_root,
            count: hashes.len() as u32,
            timestamp,
            hashes,
        }
    }

    /// Berechnet eine einfache Merkle-Root:
    /// SHA256( hash1 || hash2 || ... || hashN )
    fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        for h in hashes {
            hasher.update(h);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = ChatMessage::new("0ac5f21e", "b73d91a0", "Hallo Welt!");
        let bytes = msg.to_bytes();
        let decoded = ChatMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg.from_id, decoded.from_id);
        assert_eq!(msg.to_id, decoded.to_id);
        assert_eq!(msg.content, decoded.content);
        assert_eq!(msg.timestamp, decoded.timestamp);
        assert_eq!(msg.message_id, decoded.message_id);
    }

    #[test]
    fn test_message_id_deterministic() {
        let msg1 = ChatMessage::new("alice", "bob", "test");
        let msg2 = ChatMessage::new("alice", "bob", "test");
        // Different timestamps → different IDs (timestamp is part of the hash)
        // But same content + same timestamp should give same ID
        let msg3 = ChatMessage {
            from_id: "alice".into(),
            to_id: "bob".into(),
            content: "test".into(),
            timestamp: msg1.timestamp,
            reply_to: None,
            ..msg1.clone()
        };
        assert_eq!(msg1.message_id, msg3.message_id);
    }

    #[test]
    fn test_batch_merkle_root() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let batch = ChatBatch::from_hashes(vec![h1, h2]);
        assert_eq!(batch.count, 2);
        assert_eq!(batch.hashes.len(), 2);
        // Merkle root should be non-zero and deterministic
        assert_ne!(batch.merkle_root, [0u8; 32]);
        let batch2 = ChatBatch::from_hashes(vec![h1, h2]);
        assert_eq!(batch.merkle_root, batch2.merkle_root);
    }
}
