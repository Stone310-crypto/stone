//! Off-Chain Document Pool für StoneChain.
//!
//! ## Konzept
//!
//! Dokument-Uploads werden nicht mehr direkt in einen Block geschrieben
//! (was nur der ausgewählte Validator darf), sondern in einen gemeinsamen Pool
//! gespeichert. Beim nächsten Block-Minting drained der Validator den Pool
//! und schreibt die Dokumente on-chain.
//!
//! ## Ablauf
//!
//! 1. User lädt Dokument hoch → `DocumentPool::add_document()`
//! 2. Dokument wird sofort als "pending" gespeichert
//! 3. Beim Block-Minting: `drain_for_block()` sammelt alle pending Docs
//! 4. Validator minted Block mit den Dokumenten
//! 5. Alle Nodes akzeptieren den Block per P2P-Sync

use crate::blockchain::{Document, data_dir};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDocument {
    pub document: Document,
    pub uploaded_by_id: String,
    pub uploaded_by_name: String,
    pub uploaded_at: i64,
}

pub struct DocumentPool {
    inner: Mutex<DocumentPoolInner>,
}

struct DocumentPoolInner {
    pending: VecDeque<PendingDocument>,
    max_pending: usize,
}

impl DocumentPool {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DocumentPoolInner {
                pending: VecDeque::new(),
                max_pending: 500,
            }),
        }
    }

    /// Fügt ein Dokument zum Pool hinzu und persistiert es auf Disk.
    /// Gibt eine Erfolgsmeldung zurück.
    pub fn add_document(
        &self,
        document: Document,
        uploaded_by_id: String,
        uploaded_by_name: String,
    ) -> Result<String, String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.pending.len() >= inner.max_pending {
            return Err("Document-Pool ist voll (max 500 pending)".to_string());
        }

        let pending = PendingDocument {
            document,
            uploaded_by_id,
            uploaded_by_name,
            uploaded_at: Utc::now().timestamp(),
        };

        inner.pending.push_back(pending);
        let total = inner.pending.len();
        // ═══ Persist auf Disk (überlebt Node-Neustarts) ═══
        if let Err(e) = inner.save_to_disk() {
            eprintln!("[doc-pool] ⚠️ Persist fehlgeschlagen: {e}");
        }
        Ok(format!("Dokument im Pool gespeichert. Pool-Größe: {total}/{}", inner.max_pending))
    }

    /// Gibt alle pending Dokumente zurück, leert den Pool und löscht die Disk-Datei.
    pub fn drain_for_block(&self) -> Vec<Document> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let docs: Vec<Document> = inner.pending
            .drain(..)
            .map(|p| p.document)
            .collect();
        // Disk-Datei löschen (Pool ist jetzt leer)
        let _ = std::fs::remove_file(DocumentPool::pool_file_path());
        docs
    }

    /// Lädt persistierte Dokumente von Disk beim Node-Start.
    pub fn load_from_disk(&self) -> Result<usize, String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.load_from_disk()
    }

    fn pool_file_path() -> String {
        let dir = data_dir();
        let _ = std::fs::create_dir_all(&format!("{dir}/document_pool"));
        format!("{dir}/document_pool/pending.json")
    }

    /// Anzahl pending Dokumente.
    pub fn pending_count(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.pending.len()
    }

    /// Gibt true zurück wenn der Pool Dokumente enthält.
    pub fn has_pending(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        !inner.pending.is_empty()
    }

    /// Sucht ein Dokument im Pool anhand seiner doc_id.
    /// Gibt das Dokument sowie Metadaten zurück.
    pub fn find_document(&self, doc_id: &str) -> Option<(Document, String, String)> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.pending.iter()
            .find(|p| p.document.doc_id == doc_id)
            .map(|p| (p.document.clone(), p.uploaded_by_id.clone(), p.uploaded_by_name.clone()))
    }

    /// Liest die Rohdaten eines Dokuments aus dem Pool.
    /// Rekonstruiert sie aus den Chunks.
    pub fn read_document_data(&self, doc_id: &str) -> Option<Vec<u8>> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let doc = inner.pending.iter()
            .find(|p| p.document.doc_id == doc_id)
            .map(|p| p.document.clone())?;

        // Rekonstruiere Daten aus Chunks
        let store = crate::storage::ChunkStore::new().ok()?;
        store.reconstruct_document(&doc).ok()
    }
}

impl Default for DocumentPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── Disk-Persistenz ──────────────────────────────────────────────────────────

impl DocumentPoolInner {
    /// Lädt pending Documents von Disk (existierende Chunks bleiben erhalten).
    pub fn load_from_disk(&mut self) -> Result<usize, String> {
        let path = DocumentPool::pool_file_path();
        if !std::path::Path::new(&path).exists() {
            return Ok(0);
        }
        let data = std::fs::read_to_string(&path)
            .map_err(|e| format!("Pool-Datei lesen: {e}"))?;
        let docs: Vec<PendingDocument> = serde_json::from_str(&data)
            .map_err(|e| format!("Pool-Daten parsen: {e}"))?;
        let count = docs.len();
        self.pending.extend(docs);
        println!("[doc-pool] 📂 {count} pending Documents von Disk geladen");
        Ok(count)
    }

    /// Speichert pending Documents auf Disk.
    fn save_to_disk(&self) -> Result<(), String> {
        let path = DocumentPool::pool_file_path();
        let entries: Vec<&PendingDocument> = self.pending.iter().collect();
        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| format!("Pool serialisieren: {e}"))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Pool schreiben: {e}"))?;
        Ok(())
    }
}
