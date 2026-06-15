//! SPV (Simplified Payment Verification) Endpunkte für Light-Clients.
//!
//! ## Zweck
//!
//! Mobile-Apps und andere ressourcenbeschränkte Clients sollen NFT-Ownership,
//! Token-Transfers und Block-Anchors **trustless** verifizieren können – ohne
//! die komplette Chain (mehrere GB) herunterladen zu müssen.
//!
//! Trust-Modell: Client speichert nur den **Genesis-Hash** out-of-band und
//! folgt der Header-Chain vorwärts. Jeder Header bindet seinen Vorgänger via
//! `previous_hash` und enthält den `merkle_root` der enthaltenen Items. Damit
//! verifiziert der Client jede TX-/Document-Inklusion lokal nur mit Hashes,
//! ohne den Master als vertrauenswürdig anzunehmen.
//!
//! ## Endpunkte
//!
//! | Methode | Pfad                              | Zweck                                |
//! |--------:|-----------------------------------|--------------------------------------|
//! | GET     | `/api/v1/spv/headers`             | Range von Block-Headern (paged)      |
//! | GET     | `/api/v1/spv/tx/:tx_id/proof`     | Inklusion-Proof für eine Transaktion |
//! | GET     | `/api/v1/spv/doc/:doc_id/proof`   | Inklusion-Proof für ein Dokument     |
//! | GET     | `/api/v1/spv/tip`                 | Aktueller Chain-Tip (Header)         |
//!
//! ## Proof-Schema
//!
//! `compute_merkle_root` in `blockchain.rs` ist kein binärer Merkle-Tree,
//! sondern ein flacher Sort-then-Concat-Hash. Daher liefert der Server alle
//! Leaf-Hashes des Blocks; der Client rekonstruiert die Root und vergleicht
//! sie mit `header.merkle_root`. Bei typischen Blöcken (< 100 Items) ist die
//! Proof-Größe < 4 KB – akzeptabel für mobile Bandbreite.
//!
//! Eine spätere Migration auf einen echten binären Merkle-Tree wäre möglich,
//! erfordert aber einen Konsens-Breaking-Change.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::state::AppState;

/// Kompakter Block-Header für Light-Clients.
///
/// Enthält genau die Felder, die für Hash-Re-Computation und PoA-Signatur-
/// Verifikation gebraucht werden. Felder mit "geht in calculate_hash ein" sind
/// für die Header-Verkettung essenziell.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockHeader {
    pub index: u64,
    pub timestamp: i64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub data_size: u64,
    pub signer: String,
    pub hash: String,
    /// PoA: Ed25519-Pubkey des Validators (Hex)
    pub validator_pub_key: String,
    /// PoA: Ed25519-Signatur über `hash` (Hex)
    pub validator_signature: String,
    /// Hash über storage_proof – geht in calculate_hash ein
    pub storage_proof_hash: String,
    /// Hash über storage_challenges – geht in calculate_hash ein
    pub network_challenges_hash: String,
    /// Hash über challenge_responses – geht in calculate_hash ein
    pub challenge_responses_hash: String,
    /// Hash über chat_batches – geht in calculate_hash ein
    pub chat_batches_hash: String,
    pub pow_nonce: u64,
    pub pow_hash: String,
    pub pow_difficulty: u32,
    pub effective_difficulty: u32,
    /// Anzahl Dokumente (für UI-Anzeige, NICHT konsensrelevant)
    pub doc_count: u32,
    /// Anzahl Tombstones (für UI-Anzeige, NICHT konsensrelevant)
    pub tombstone_count: u32,
    /// Anzahl Token-TXs (für UI-Anzeige, NICHT konsensrelevant)
    pub tx_count: u32,
}

impl BlockHeader {
    /// Konvertiert einen vollen Block in einen kompakten Header.
    pub fn from_block(b: &stone::blockchain::Block) -> Self {
        Self {
            index: b.index,
            timestamp: b.timestamp,
            previous_hash: b.previous_hash.clone(),
            merkle_root: b.merkle_root.clone(),
            data_size: b.data_size,
            signer: b.signer.clone(),
            hash: b.hash.clone(),
            validator_pub_key: b.validator_pub_key.clone(),
            validator_signature: b.validator_signature.clone(),
            storage_proof_hash: stone::storage_proof::storage_proof_hash(&b.storage_proof),
            network_challenges_hash: stone::storage_proof::network_challenges_hash(&b.storage_challenges),
            challenge_responses_hash: stone::storage_proof::challenge_responses_hash(&b.challenge_responses),
            chat_batches_hash: stone::merkle_batch::chat_batches_hash(&b.chat_batches),
            pow_nonce: b.pow_nonce,
            pow_hash: b.pow_hash.clone(),
            pow_difficulty: b.pow_difficulty,
            effective_difficulty: b.effective_difficulty,
            doc_count: b.documents.len() as u32,
            tombstone_count: b.tombstones.len() as u32,
            tx_count: b.transactions.len() as u32,
        }
    }
}

#[derive(Deserialize)]
pub struct HeadersQuery {
    /// Erster Block-Index (default: 0)
    #[serde(default)]
    pub from: Option<u64>,
    /// Anzahl Header (default: 256, max: 1024)
    #[serde(default)]
    pub count: Option<u32>,
}

#[derive(Serialize)]
pub struct HeadersResponse {
    pub from: u64,
    pub count: usize,
    pub chain_tip: u64,
    pub headers: Vec<BlockHeader>,
}

/// GET /api/v1/spv/headers?from=0&count=256
///
/// Liefert einen Range von Block-Headern. Light-Client startet bei `from=0`
/// (oder ab seinem zuletzt validierten Header) und pagt sich vorwärts.
pub async fn handle_spv_headers(
    Query(q): Query<HeadersQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let from = q.from.unwrap_or(0);
    // Cap auf 1024 verhindert DoS (>1 MB Response wäre möglich).
    let count = q.count.unwrap_or(256).min(1024) as usize;

    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    let chain_tip = chain.blocks.len().saturating_sub(1) as u64;

    let headers: Vec<BlockHeader> = chain.blocks.iter()
        .skip(from as usize)
        .take(count)
        .map(BlockHeader::from_block)
        .collect();
    drop(chain);

    let len = headers.len();
    (StatusCode::OK, Json(HeadersResponse {
        from,
        count: len,
        chain_tip,
        headers,
    })).into_response()
}

/// GET /api/v1/spv/tip
///
/// Liefert nur den aktuellen Chain-Tip-Header. Polling-Endpoint für Light-
/// Clients: "Habe ich den neuesten Block?" – bei Mismatch wird `/headers`
/// inkrementell nachgeladen.
pub async fn handle_spv_tip(State(state): State<AppState>) -> impl IntoResponse {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
    match chain.blocks.last() {
        Some(b) => {
            let header = BlockHeader::from_block(b);
            (StatusCode::OK, Json(header)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "chain empty"})),
        ).into_response(),
    }
}

/// Inklusion-Proof für eine einzelne TX oder ein einzelnes Dokument.
///
/// Der Client verifiziert lokal:
///   1. SHA256(target_leaf_preimage) == one of leaf_hashes
///   2. SHA256(sorted_concat(leaf_hashes)) == header.merkle_root
///   3. header.hash == recompute_hash(header)  (Block-Hash-Konsistenz)
///   4. Ed25519-Verify(header.validator_pub_key, header.hash, header.validator_signature)
///   5. Header-Kette korrekt verbunden bis Genesis (vorher via /headers gesynced)
#[derive(Serialize)]
pub struct InclusionProof {
    pub header: BlockHeader,
    /// Alle Leaf-Hashes des Blocks, in der Form wie sie in `compute_merkle_root`
    /// hashed werden (32-Byte SHA256 als 64-Hex-String). Reihenfolge: vor dem
    /// Sort wie in `compute_merkle_root` (Client muss sortieren).
    pub leaf_hashes: Vec<String>,
    /// Index des Ziel-Leafs in der UNSORTIERTEN Liste (zur schnellen Identifikation).
    pub target_leaf_index: usize,
    /// Hex-codierter Leaf-Hash des Ziels (für direkten Vergleich).
    pub target_leaf_hash: String,
    /// Kind: "tx" | "document" | "tombstone"
    pub target_kind: String,
    /// Pre-Image-Bytes des Leafs (damit der Client den Hash unabhängig
    /// rekonstruieren kann). Hex-codiert.
    pub target_preimage_hex: String,
}

/// Berechnet den Leaf-Hash genauso wie `compute_merkle_root` es tut.
///
/// **WICHTIG:** Bei Änderungen an `compute_merkle_root` müssen beide Funktionen
/// synchron gehalten werden – sonst stimmen Server-Proofs nicht mit der Chain.
fn leaf_hash_document(doc: &stone::blockchain::Document) -> ([u8; 32], Vec<u8>) {
    let mut preimage = Vec::with_capacity(
        doc.doc_id.len() + doc.content_type.len() + 32,
    );
    preimage.extend_from_slice(doc.doc_id.as_bytes());
    preimage.push(b'|');
    preimage.extend_from_slice(&doc.version.to_le_bytes());
    preimage.push(b'|');
    preimage.extend_from_slice(&doc.size.to_le_bytes());
    preimage.push(b'|');
    preimage.extend_from_slice(doc.content_type.as_bytes());
    let h: [u8; 32] = Sha256::digest(&preimage).into();
    (h, preimage)
}

fn leaf_hash_tombstone(t: &stone::blockchain::DocumentTombstone) -> ([u8; 32], Vec<u8>) {
    let mut preimage = Vec::with_capacity(4 + t.doc_id.len());
    preimage.extend_from_slice(b"del:");
    preimage.extend_from_slice(t.doc_id.as_bytes());
    let h: [u8; 32] = Sha256::digest(&preimage).into();
    (h, preimage)
}

fn leaf_hash_tx(tx: &stone::token::TokenTx) -> ([u8; 32], Vec<u8>) {
    let mut preimage = Vec::with_capacity(3 + tx.tx_id.len());
    preimage.extend_from_slice(b"tx:");
    preimage.extend_from_slice(tx.tx_id.as_bytes());
    let h: [u8; 32] = Sha256::digest(&preimage).into();
    (h, preimage)
}

/// Sammelt alle Leaf-Hashes eines Blocks **in der ursprünglichen Reihenfolge**
/// (vor dem Sort). Der Client muss die Liste selbst sortieren, bevor er die
/// Merkle-Root rekonstruiert.
fn collect_block_leaves(b: &stone::blockchain::Block) -> Vec<String> {
    let mut leaves: Vec<String> = Vec::with_capacity(
        b.documents.len() + b.tombstones.len() + b.transactions.len(),
    );
    for doc in &b.documents {
        let (h, _) = leaf_hash_document(doc);
        leaves.push(hex::encode(h));
    }
    for t in &b.tombstones {
        let (h, _) = leaf_hash_tombstone(t);
        leaves.push(hex::encode(h));
    }
    for tx in &b.transactions {
        let (h, _) = leaf_hash_tx(tx);
        leaves.push(hex::encode(h));
    }
    leaves
}

/// GET /api/v1/spv/tx/:tx_id/proof
pub async fn handle_spv_tx_proof(
    Path(tx_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());

    // Linear-Scan reicht hier: Light-Client ruft das selten auf und der Master
    // hat die Chain im RAM. Bei Bedarf später durch tx_id → block_index Index
    // ersetzen.
    for b in chain.blocks.iter() {
        if let Some((tx_idx, tx)) = b.transactions.iter().enumerate()
            .find(|(_, tx)| tx.tx_id == tx_id)
        {
            let (h, preimage) = leaf_hash_tx(tx);
            let leaves = collect_block_leaves(b);
            // Offset im kombinierten Leaf-Vektor: docs + tombstones + tx_idx
            let target_leaf_index = b.documents.len() + b.tombstones.len() + tx_idx;
            let header = BlockHeader::from_block(b);
            drop(chain);
            return (StatusCode::OK, Json(InclusionProof {
                header,
                leaf_hashes: leaves,
                target_leaf_index,
                target_leaf_hash: hex::encode(h),
                target_kind: "tx".to_string(),
                target_preimage_hex: hex::encode(&preimage),
            })).into_response();
        }
    }
    drop(chain);
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "tx not found", "tx_id": tx_id})),
    ).into_response()
}

/// GET /api/v1/spv/doc/:doc_id/proof
pub async fn handle_spv_doc_proof(
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());

    // Wir suchen den NEUESTEN Block der dieses Dokument enthält (Versionen)
    // – relevant fürs Item-Ownership: jüngste Version = aktueller Stand.
    for b in chain.blocks.iter().rev() {
        if let Some((doc_idx, doc)) = b.documents.iter().enumerate()
            .find(|(_, d)| d.doc_id == doc_id)
        {
            let (h, preimage) = leaf_hash_document(doc);
            let leaves = collect_block_leaves(b);
            let target_leaf_index = doc_idx;
            let header = BlockHeader::from_block(b);
            drop(chain);
            return (StatusCode::OK, Json(InclusionProof {
                header,
                leaf_hashes: leaves,
                target_leaf_index,
                target_leaf_hash: hex::encode(h),
                target_kind: "document".to_string(),
                target_preimage_hex: hex::encode(&preimage),
            })).into_response();
        }
    }
    drop(chain);
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "document not found", "doc_id": doc_id})),
    ).into_response()
}

// ── Item-Proof ───────────────────────────────────────────────────────────────
//
// Game-Items (NFTs) leben im `GameEconomyStore` (off-chain Index), werden aber
// bei jedem Mint via Anchor-TX on-chain festgeschrieben. Die TX-ID landet im
// Item-Metadata-Feld `anchor_tx_id`. Damit kann ein Light-Client die Mint-
// Existenz und den ursprünglichen Empfänger verifizieren.
//
// **Heutige Garantie:** Mint + jeder Marketplace-Sale ist trustless verifizierbar.
// Der Buy-Handler in `game.rs` schreibt für jeden Sale eine `transfer_history`-
// Entry ins Item-Metadata (mit `tx_id`, `from`, `to`, `kind: "sale"`, `ts`) und
// markiert die zugehörige Token-TX-Memo mit `[item:<id>]`. Light-Clients können
// die ganze Owner-Kette via `/api/v1/spv/item/{id}/history` rekonstruieren.
//
// **Nicht abgedeckt:** Direkte P2P-Item-Transfers (außerhalb des Marketplace)
// gibt es heute nicht. Burns sind on-chain noch nicht verankert.

/// Schlanke Item-Info für SPV-Response (alle Felder die wir hier ungewichtet
/// auf dem Wire schicken – keine Metadata-Dumps).
#[derive(Serialize)]
pub struct ItemInfo {
    pub item_id: String,
    pub name: String,
    pub category: String,
    pub rarity: String,
    pub owner: String,
    pub game_id: String,
    pub creator: String,
    pub created_at: i64,
    pub transferable: bool,
    pub burned: bool,
}

#[derive(Serialize)]
pub struct ItemProofResponse {
    /// Off-chain Item-Daten aus dem GameEconomyStore (NICHT direkt verifizierbar;
    /// der Client muss `mint_proof` prüfen, um die Mint-Existenz zu bestätigen).
    pub item: ItemInfo,
    /// Anchor-TX-ID aus `item.metadata.anchor_tx_id`. Wenn vorhanden, ist
    /// `mint_proof` gesetzt; sonst fehlte der Anchor (Legacy- oder ungültiges Item).
    pub anchor_tx_id: Option<String>,
    /// Vollständiger Inklusion-Proof für die Anchor-TX. Erlaubt dem Client,
    /// kryptografisch zu prüfen, dass die Mint-TX in einem signierten Block
    /// liegt, der von einer validen Header-Chain abstammt.
    pub mint_proof: Option<InclusionProof>,
}

/// GET /api/v1/spv/item/:item_id/proof
pub async fn handle_spv_item_proof(
    Path(item_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    // 1) Item aus Game-Store laden
    let (item_info, anchor_tx_id) = {
        let store = state.node.game_economy.read().unwrap_or_else(|e| e.into_inner());
        match store.items.get(&item_id) {
            Some(item) => {
                let info = ItemInfo {
                    item_id: item.item_id.clone(),
                    name: item.name.clone(),
                    category: item.category.clone(),
                    rarity: format!("{:?}", item.rarity).to_lowercase(),
                    owner: item.owner.clone(),
                    game_id: item.game_id.clone(),
                    creator: item.creator.clone(),
                    created_at: item.created_at,
                    transferable: item.transferable,
                    burned: item.burned,
                };
                let anchor = item.metadata.get("anchor_tx_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                (info, anchor)
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "item not found", "item_id": item_id})),
                ).into_response();
            }
        }
    };

    // 2) Anchor-TX in Chain finden (falls vorhanden)
    let mint_proof = if let Some(ref tx_id) = anchor_tx_id {
        let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut found: Option<InclusionProof> = None;
        'search: for b in chain.blocks.iter() {
            if let Some((tx_idx, tx)) = b.transactions.iter().enumerate()
                .find(|(_, tx)| &tx.tx_id == tx_id)
            {
                let (h, preimage) = leaf_hash_tx(tx);
                let leaves = collect_block_leaves(b);
                let target_leaf_index = b.documents.len() + b.tombstones.len() + tx_idx;
                let header = BlockHeader::from_block(b);
                found = Some(InclusionProof {
                    header,
                    leaf_hashes: leaves,
                    target_leaf_index,
                    target_leaf_hash: hex::encode(h),
                    target_kind: "tx".to_string(),
                    target_preimage_hex: hex::encode(&preimage),
                });
                break 'search;
            }
        }
        drop(chain);
        found
    } else {
        None
    };

    (StatusCode::OK, Json(ItemProofResponse {
        item: item_info,
        anchor_tx_id,
        mint_proof,
    })).into_response()
}

// ── Item-History (Phase 1.6) ────────────────────────────────────────────────
//
// Liefert die komplette Owner-Kette eines Items als verkettete Liste von
// Anchor-TX-Proofs:
//   [
//     { kind: "mint", from: "...creator...", to: "...first_owner...", tx_id, proof },
//     { kind: "sale", from: "...seller...",  to: "...buyer...",       tx_id, proof },
//     ...
//   ]
//
// Der Light-Client verifiziert:
//   1. Jeder `proof` ist gültig (Inklusion + Header-Chain + Signatur)
//   2. Jede TX-Memo trägt `[item:<id>]`-Marker für die richtige Item-ID
//   3. `from`/`to` der Entries verkettet (to_n == from_{n+1})
//   4. Letzte `to` == `item.owner` (aus separatem ItemProof oder lokalem Cache)
//
// Damit ist der aktuelle Besitzer eines Items trustless rekonstruierbar.

#[derive(Serialize)]
pub struct HistoryEntry {
    /// "mint" | "sale"
    pub kind: String,
    pub tx_id: String,
    pub from: String,
    pub to: String,
    pub ts: i64,
    /// SPV-Proof für die Anchor-TX. None wenn die TX (noch) nicht in einem
    /// finalisierten Block liegt – z.B. wenn ein Sale gerade erst gepostet
    /// wurde. Der Client sollte solche Entries als "pending" behandeln.
    pub proof: Option<InclusionProof>,
}

#[derive(Serialize)]
pub struct ItemHistoryResponse {
    pub item_id: String,
    pub current_owner: String,
    pub burned: bool,
    pub entries: Vec<HistoryEntry>,
}

/// GET /api/v1/spv/item/:item_id/history
pub async fn handle_spv_item_history(
    Path(item_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    // 1) Item + raw history aus dem Game-Store extrahieren.
    let (current_owner, burned, mint_anchor, mint_ts, sale_entries): (
        String,
        bool,
        Option<String>,
        i64,
        Vec<(String, String, String, i64)>, // (tx_id, from, to, ts)
    ) = {
        let store = state.node.game_economy.read().unwrap_or_else(|e| e.into_inner());
        let item = match store.items.get(&item_id) {
            Some(i) => i,
            None => return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "item not found", "item_id": item_id})),
            ).into_response(),
        };
        let mint_anchor = item.metadata.get("anchor_tx_id")
            .and_then(|v| v.as_str()).map(|s| s.to_string());
        let sales: Vec<(String, String, String, i64)> = item.metadata
            .get("transfer_history")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|e| {
                let obj = e.as_object()?;
                if obj.get("kind").and_then(|v| v.as_str()) != Some("sale") { return None; }
                Some((
                    obj.get("tx_id")?.as_str()?.to_string(),
                    obj.get("from")?.as_str()?.to_string(),
                    obj.get("to")?.as_str()?.to_string(),
                    obj.get("ts").and_then(|v| v.as_i64()).unwrap_or(0),
                ))
            }).collect())
            .unwrap_or_default();
        (item.owner.clone(), item.burned, mint_anchor, item.created_at, sales)
    };

    // 2) Für jede Anchor-TX einen Proof + die echten TX-Felder finden.
    //
    //    Wir lesen `from`/`to` direkt aus der on-chain TX – das ist die einzige
    //    verifizierbare Quelle für Light-Clients. Bei einer noch nicht
    //    finalisierten Sale-TX fallen wir auf die Metadata-Werte zurück, der
    //    Proof bleibt dann `None` (Pending).
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());

    // Sucht TX + erzeugt direkt den Proof. Lineare Scan, akzeptabel bei
    // typischer Chain-Länge; bei >50k Blöcken wäre ein tx_id-Index sinnvoll.
    let find_tx_and_proof = |tx_id: &str| -> Option<(stone::token::TokenTx, InclusionProof)> {
        for b in chain.blocks.iter() {
            if let Some((tx_idx, tx)) = b.transactions.iter().enumerate()
                .find(|(_, tx)| tx.tx_id == tx_id)
            {
                let (h, preimage) = leaf_hash_tx(tx);
                let leaves = collect_block_leaves(b);
                let target_leaf_index = b.documents.len() + b.tombstones.len() + tx_idx;
                let header = BlockHeader::from_block(b);
                let proof = InclusionProof {
                    header,
                    leaf_hashes: leaves,
                    target_leaf_index,
                    target_leaf_hash: hex::encode(h),
                    target_kind: "tx".to_string(),
                    target_preimage_hex: hex::encode(&preimage),
                };
                return Some((tx.clone(), proof));
            }
        }
        None
    };

    let mut entries: Vec<HistoryEntry> = Vec::new();

    if let Some(tx_id) = mint_anchor {
        match find_tx_and_proof(&tx_id) {
            Some((tx, proof)) => entries.push(HistoryEntry {
                kind: "mint".to_string(),
                tx_id,
                from: tx.from,
                to: tx.to,
                ts: mint_ts,
                proof: Some(proof),
            }),
            None => entries.push(HistoryEntry {
                kind: "mint".to_string(),
                tx_id,
                from: String::new(),
                to: String::new(),
                ts: mint_ts,
                proof: None,
            }),
        }
    }

    for (tx_id, meta_from, meta_to, ts) in sale_entries {
        match find_tx_and_proof(&tx_id) {
            Some((tx, proof)) => entries.push(HistoryEntry {
                kind: "sale".to_string(),
                tx_id,
                from: tx.from,
                to: tx.to,
                ts,
                proof: Some(proof),
            }),
            None => entries.push(HistoryEntry {
                kind: "sale".to_string(),
                tx_id,
                from: meta_from,
                to: meta_to,
                ts,
                proof: None,
            }),
        }
    }

    drop(chain);

    (StatusCode::OK, Json(ItemHistoryResponse {
        item_id,
        current_owner,
        burned,
        entries,
    })).into_response()
}
