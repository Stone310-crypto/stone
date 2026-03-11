//! Merkle-Batch System für StoneChain Chat.
//!
//! Fasst Chat-Nachrichten aus dem MessagePool zu einem Merkle-Batch zusammen.
//! Nur der Merkle-Root-Hash landet als `ChatBatchAnchor` im Block.
//! Jede einzelne Nachricht bleibt kryptografisch beweisbar über ihren Merkle-Proof.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::message_pool::PooledMessage;

// ─── ChatBatchAnchor ─────────────────────────────────────────────────────────

/// Anker-Struktur die in den Block eingebettet wird.
/// Repräsentiert einen Batch von Chat-Nachrichten, von dem nur der Merkle-Root
/// in den Block-Hash eingeht. Die einzelnen Nachrichten bleiben off-chain.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ChatBatchAnchor {
    /// Merkle-Root-Hash über alle Nachrichten-Leaf-Hashes (64 Hex-Zeichen)
    pub merkle_root: String,
    /// Anzahl der Nachrichten in diesem Batch
    pub batch_size: u32,
    /// Erste Sequenznummer im Batch
    pub seq_start: u64,
    /// Letzte Sequenznummer im Batch
    pub seq_end: u64,
    /// Zeitpunkt der Batch-Erstellung (Unix-Timestamp)
    pub timestamp: i64,
    /// Volle Nachrichten – reisen mit dem Block über P2P,
    /// damit jeder Node den Chat-Index aufbauen kann.
    #[serde(default)]
    pub messages: Vec<PooledMessage>,
}

// ─── Merkle-Tree ─────────────────────────────────────────────────────────────

/// Standard binärer Merkle-Tree.
///
/// Blätter = `PooledMessage::leaf_hash()` (SHA-256 über msg_id + sequence).
/// Innere Knoten = `SHA-256(left || right)`.
/// Bei ungerader Blattanzahl wird das letzte Blatt dupliziert.
pub struct MerkleTree {
    root: [u8; 32],
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Baut einen Merkle-Tree aus den gegebenen Leaf-Hashes.
    ///
    /// Gibt einen leeren Tree zurück falls `leaves` leer ist.
    pub fn build(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            return MerkleTree {
                root: [0u8; 32],
                layers: vec![],
            };
        }

        let mut layers: Vec<Vec<[u8; 32]>> = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();

        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + 1) / 2);
            for pair in current.chunks(2) {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                let mut h = Sha256::new();
                h.update(left);
                h.update(right);
                next.push(h.finalize().into());
            }
            layers.push(next.clone());
            current = next;
        }

        MerkleTree {
            root: current[0],
            layers,
        }
    }

    /// Merkle-Root als Hex-String.
    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
    }

    /// Merkle-Root als Byte-Array.
    pub fn root_bytes(&self) -> [u8; 32] {
        self.root
    }

    /// Erzeugt einen Merkle-Proof für das Blatt an Position `index`.
    ///
    /// Der Proof besteht aus den Geschwister-Hashes auf dem Pfad zur Wurzel,
    /// zusammen mit der Seitenangabe (links/rechts).
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if self.layers.is_empty() || index >= self.layers[0].len() {
            return None;
        }

        let leaf_hash = self.layers[0][index];
        let mut siblings = Vec::new();
        let mut idx = index;

        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_idx = if idx % 2 == 0 {
                // Geschwister rechts (oder selbst falls letzte)
                if idx + 1 < layer.len() { idx + 1 } else { idx }
            } else {
                // Geschwister links
                idx - 1
            };

            siblings.push(ProofNode {
                hash: layer[sibling_idx],
                is_right: sibling_idx > idx,
            });

            idx /= 2;
        }

        Some(MerkleProof {
            leaf_hash,
            siblings,
        })
    }

    /// Anzahl der Blätter im Tree.
    pub fn leaf_count(&self) -> usize {
        self.layers.first().map(|l| l.len()).unwrap_or(0)
    }
}

// ─── Merkle-Proof ────────────────────────────────────────────────────────────

/// Beweis, dass eine Nachricht in einem bestimmten Batch enthalten ist.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleProof {
    /// Hash des Blattes (leaf_hash der Nachricht)
    pub leaf_hash: [u8; 32],
    /// Geschwister-Knoten auf dem Pfad zur Wurzel
    pub siblings: Vec<ProofNode>,
}

/// Ein Knoten im Merkle-Proof-Pfad.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofNode {
    /// Hash des Geschwister-Knotens
    pub hash: [u8; 32],
    /// true = Geschwister sitzt rechts, false = links
    pub is_right: bool,
}

impl MerkleProof {
    /// Verifiziert den Proof gegen einen erwarteten Root-Hash.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let mut current = self.leaf_hash;
        for node in &self.siblings {
            let mut h = Sha256::new();
            if node.is_right {
                h.update(current);
                h.update(node.hash);
            } else {
                h.update(node.hash);
                h.update(current);
            }
            current = h.finalize().into();
        }
        current == *expected_root
    }
}

// ─── Batch-Builder ───────────────────────────────────────────────────────────

/// Erstellt einen `ChatBatchAnchor` aus einer Liste von Pool-Nachrichten.
///
/// Die Nachrichten müssen bereits `drain_for_batch()` entnommen sein
/// und eine gültige `sequence` haben.
pub fn build_batch(messages: &[PooledMessage]) -> Option<(ChatBatchAnchor, MerkleTree)> {
    if messages.is_empty() {
        return None;
    }

    // Leaf-Hashes berechnen
    let leaves: Vec<[u8; 32]> = messages.iter().map(|m| m.leaf_hash()).collect();

    // Merkle-Tree bauen
    let tree = MerkleTree::build(&leaves);

    let anchor = ChatBatchAnchor {
        merkle_root: tree.root_hex(),
        batch_size: messages.len() as u32,
        seq_start: messages.first().map(|m| m.sequence).unwrap_or(0),
        seq_end: messages.last().map(|m| m.sequence).unwrap_or(0),
        timestamp: chrono::Utc::now().timestamp(),
        messages: messages.to_vec(),
    };

    Some((anchor, tree))
}

/// Berechnet einen deterministischen Hash über alle ChatBatchAnchors eines Blocks.
///
/// Wird in `calculate_hash()` aufgerufen um die Chat-Batches im Block-Hash zu verankern.
/// Leere Batches → "0" × 64 (keine Auswirkung auf den Hash).
pub fn chat_batches_hash(batches: &[ChatBatchAnchor]) -> String {
    if batches.is_empty() {
        return "0".repeat(64);
    }
    let mut h = Sha256::new();
    h.update(b"chat_batches:");
    for batch in batches {
        h.update(batch.merkle_root.as_bytes());
        h.update(batch.batch_size.to_le_bytes());
        h.update(batch.seq_start.to_le_bytes());
        h.update(batch.seq_end.to_le_bytes());
        h.update(batch.timestamp.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}

/// Erzeugt einen Merkle-Proof für eine bestimmte Nachricht in einem Batch.
///
/// Sucht die Nachricht anhand ihrer `msg_id` und gibt den Proof zurück.
pub fn proof_for_message(
    messages: &[PooledMessage],
    tree: &MerkleTree,
    msg_id: &str,
) -> Option<MerkleProof> {
    let idx = messages.iter().position(|m| m.msg_id == msg_id)?;
    tree.proof(idx)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Erzeugt einen Fake-Leaf-Hash aus einem einfachen Index.
    fn fake_leaf(i: u8) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([i]);
        h.finalize().into()
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![fake_leaf(1)];
        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.root_bytes(), leaves[0]);
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let leaves = vec![fake_leaf(1), fake_leaf(2)];
        let tree = MerkleTree::build(&leaves);

        // Root = SHA-256(leaf0 || leaf1)
        let mut h = Sha256::new();
        h.update(leaves[0]);
        h.update(leaves[1]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(tree.root_bytes(), expected);
    }

    #[test]
    fn test_merkle_tree_three_leaves_odd() {
        let leaves = vec![fake_leaf(1), fake_leaf(2), fake_leaf(3)];
        let tree = MerkleTree::build(&leaves);

        // Layer 0: [L0, L1, L2]
        // Layer 1: [H(L0,L1), H(L2,L2)]  (L2 dupliziert)
        // Layer 2: [H(H01, H22)]
        let mut h01 = Sha256::new();
        h01.update(leaves[0]);
        h01.update(leaves[1]);
        let h01: [u8; 32] = h01.finalize().into();

        let mut h22 = Sha256::new();
        h22.update(leaves[2]);
        h22.update(leaves[2]);
        let h22: [u8; 32] = h22.finalize().into();

        let mut root = Sha256::new();
        root.update(h01);
        root.update(h22);
        let expected: [u8; 32] = root.finalize().into();

        assert_eq!(tree.root_bytes(), expected);
        assert_eq!(tree.leaf_count(), 3);
    }

    #[test]
    fn test_merkle_proof_two_leaves() {
        let leaves = vec![fake_leaf(1), fake_leaf(2)];
        let tree = MerkleTree::build(&leaves);
        let root = tree.root_bytes();

        // Proof für Leaf 0
        let proof0 = tree.proof(0).unwrap();
        assert!(proof0.verify(&root));

        // Proof für Leaf 1
        let proof1 = tree.proof(1).unwrap();
        assert!(proof1.verify(&root));
    }

    #[test]
    fn test_merkle_proof_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4).map(fake_leaf).collect();
        let tree = MerkleTree::build(&leaves);
        let root = tree.root_bytes();

        for i in 0..4 {
            let proof = tree.proof(i).expect("proof should exist");
            assert!(proof.verify(&root), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn test_merkle_proof_invalid_root() {
        let leaves = vec![fake_leaf(1), fake_leaf(2)];
        let tree = MerkleTree::build(&leaves);

        let proof = tree.proof(0).unwrap();
        let fake_root = [0xFFu8; 32];
        assert!(!proof.verify(&fake_root));
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let leaves = vec![fake_leaf(1)];
        let tree = MerkleTree::build(&leaves);
        assert!(tree.proof(1).is_none());
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::build(&[]);
        assert_eq!(tree.root_bytes(), [0u8; 32]);
        assert_eq!(tree.leaf_count(), 0);
        assert!(tree.proof(0).is_none());
    }

    #[test]
    fn test_chat_batches_hash_empty() {
        let hash = chat_batches_hash(&[]);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, "0".repeat(64));
    }

    #[test]
    fn test_chat_batches_hash_deterministic() {
        let anchor = ChatBatchAnchor {
            merkle_root: "a".repeat(64),
            batch_size: 10,
            seq_start: 1,
            seq_end: 10,
            timestamp: 1000,
            messages: Vec::new(),
        };
        let h1 = chat_batches_hash(&[anchor.clone()]);
        let h2 = chat_batches_hash(&[anchor]);
        assert_eq!(h1, h2);
        assert_ne!(h1, "0".repeat(64));
    }

    #[test]
    fn test_build_batch_with_pooled_messages() {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::ed25519::signature::Signer;
        use rand::rngs::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let from = hex::encode(key.verifying_key().to_bytes());
        let to = hex::encode([0u8; 32]);

        let mut messages = Vec::new();
        for i in 0..5 {
            let nonce = format!("{:032x}", rand::random::<u128>());
            let ts = chrono::Utc::now().timestamp();
            let msg_id = PooledMessage::compute_msg_id(&from, &to, "dGVzdA==", &nonce, ts);
            let hash = Sha256::digest(msg_id.as_bytes());
            let sig = key.sign(&hash);

            messages.push(PooledMessage {
                msg_id: msg_id.clone(),
                sequence: i + 1,
                from_wallet: from.clone(),
                to_wallet: to.clone(),
                from_user_id: "test".into(),
                from_name: "Test".into(),
                encrypted_content: "dGVzdA==".into(),
                nonce,
                timestamp: ts,
                signature: hex::encode(sig.to_bytes()),
                status: crate::message_pool::MessageStatus::Pending,
                pow_nonce: crate::consensus::solve_message_pow(&msg_id, crate::consensus::MESSAGE_POW_DIFFICULTY),
            });
        }

        let (anchor, tree) = build_batch(&messages).expect("batch should build");
        assert_eq!(anchor.batch_size, 5);
        assert_eq!(anchor.seq_start, 1);
        assert_eq!(anchor.seq_end, 5);
        assert_eq!(anchor.merkle_root.len(), 64);

        // Proof für jede Nachricht verifizieren
        let root = tree.root_bytes();
        for (i, msg) in messages.iter().enumerate() {
            let proof = proof_for_message(&messages, &tree, &msg.msg_id)
                .expect("proof should exist");
            assert!(proof.verify(&root), "proof failed for msg {i}");
        }
    }
}
