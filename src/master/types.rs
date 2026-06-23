//! Master Node Types – Events, API-Typen, Web-of-Trust Strukturen

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::{PeerStatus, PeerInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum NodeEvent {
    /// Neuer Block wurde zur Chain hinzugefügt
    BlockAdded {
        index: u64,
        hash: String,
        docs: usize,
        owner: String,
        timestamp: i64,
    },
    /// Dokument hochgeladen/aktualisiert
    DocumentUpdated {
        doc_id: String,
        title: String,
        owner: String,
        version: u32,
        block_index: u64,
    },
    /// Dokument gelöscht (Soft-Delete)
    DocumentDeleted {
        doc_id: String,
        owner: String,
        block_index: u64,
    },
    /// Peer-Status geändert
    PeerStatusChanged {
        url: String,
        status: PeerStatus,
    },
    /// Chain-Synchronisation abgeschlossen
    SyncCompleted {
        peer_url: String,
        blocks_added: u64,
    },
    /// Integritätsfehler entdeckt
    IntegrityError {
        description: String,
    },
    /// Node gestartet
    NodeStarted {
        node_id: String,
        role: String,
        timestamp: i64,
    },
    /// Metriken-Update
    MetricsUpdate {
        blocks: u64,
        documents: u64,
        peers_healthy: u64,
        peers_total: u64,
    },
    /// Initialer Status bei WebSocket-Verbindung
    InitialState {
        node_id: String,
        role: String,
        block_height: u64,
        latest_hash: String,
        documents_total: u64,
        peers_total: usize,
        peers_healthy: usize,
        requests_total: u64,
        ws_connections: u64,
        uptime_seconds: i64,
    },
    // ─── PoA / Konsensus Events ───────────────────────────────────────────────
    /// Validator zur Whitelist hinzugefügt
    ValidatorAdded {
        node_id: String,
        pub_key_hex: String,
        name: String,
    },
    /// Validator aus der Whitelist entfernt
    ValidatorRemoved {
        node_id: String,
    },
    /// Validator deaktiviert / reaktiviert
    ValidatorStatusChanged {
        node_id: String,
        active: bool,
    },
    /// Block-Proposal erstellt und an Peers verschickt
    ProposalCreated {
        block_hash: String,
        block_index: u64,
        proposer_id: String,
        round: u64,
    },
    /// Stimme für eine Konsensus-Runde empfangen
    VoteReceived {
        round: u64,
        block_hash: String,
        voter_id: String,
        accept: bool,
        accepts: usize,
        needed: usize,
    },
    /// Konsensus für einen Block erreicht
    ConsensusReached {
        round: u64,
        block_hash: String,
        block_index: u64,
        votes_for: usize,
    },
    /// Konsensus abgelehnt (nicht genug Stimmen)
    ConsensusRejected {
        round: u64,
        block_hash: String,
        votes_for: usize,
        votes_against: usize,
        needed: usize,
    },
    /// Fork in der Chain erkannt
    ForkDetected {
        block_index: u64,
        our_hash: String,
        peer_hash: String,
        peer_url: String,
    },
    /// Fork aufgelöst
    ForkResolved {
        winning_hash: String,
        dropped_blocks: u64,
        reason: String,
    },
    // ─── Web-of-Trust Events ──────────────────────────────────────────────────
    /// Neuer Node beantragt Beitritt
    TrustJoinRequested {
        peer_id: String,
        name: Option<String>,
        timestamp: i64,
    },
    /// Node wurde durch Abstimmung genehmigt
    TrustApproved {
        peer_id: String,
        voter: String,
        votes_for: usize,
        timestamp: i64,
    },
    /// Node wurde durch Abstimmung widerrufen
    TrustRevoked {
        peer_id: String,
        voter: String,
        votes_against: usize,
        timestamp: i64,
    },
    /// Abstimmungsstimme empfangen (noch kein Quorum)
    TrustVoteCast {
        peer_id: String,
        voter: String,
        approve: bool,
        votes_for: usize,
        votes_against: usize,
        needed: usize,
        timestamp: i64,
    },
    // ─── Token-Economy Events ─────────────────────────────────────────────────
    /// Token-Transaktion in Block aufgenommen
    TokenTransfer {
        tx_id: String,
        from: String,
        to: String,
        amount: String,
        tx_type: String,
        block_index: u64,
    },
    // ─── Slashing Events ──────────────────────────────────────────────────────
    /// Validator wurde bestraft
    ValidatorSlashed {
        validator_id: String,
        offense: String,
        slashed_amount: String,
        timestamp: i64,
    },
    // ─── Chat Events ──────────────────────────────────────────────────────────
    /// Chat-Nachricht empfangen (für Echtzeit-Push an WebSocket-Clients)
    ChatMessageReceived {
        msg_id: String,
        from_wallet: String,
        to_wallet: String,
        from_name: String,
        timestamp: i64,
        /// "direct" | "group"
        channel_type: String,
        /// Gruppen-ID falls Gruppennachricht, sonst leer
        group_id: String,
    },
    // ─── Call-Signaling Events ────────────────────────────────────────────────
    /// Profil-Update (Name/Bio geändert)
    ProfileUpdated {
        user_id: String,
        name: String,
    },
    /// WebRTC Call-Signal empfangen (Offer/Answer/ICE/Hangup)
    CallSignalReceived {
        call_id: String,
        signal_type: String,
        from_wallet: String,
        to_wallet: String,
        timestamp: i64,
    },
}

// ─── Event-Bus ───────────────────────────────────────────────────────────────

/// Einfacher In-Memory Event-Bus für WebSocket-Broadcasts.
/// Subscriber registrieren sich mit einem tokio::sync::broadcast-Receiver.
#[derive(Clone)]
pub struct EventBus {
    sender: tokio::sync::broadcast::Sender<NodeEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: NodeEvent) {
        // Fehler ignorieren falls kein Subscriber aktiv ist
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<NodeEvent> {
        self.sender.subscribe()
    }
}

// ─── API-Typen ───────────────────────────────────────────────────────────────

/// Kompakte Chain-Zusammenfassung für Status-Endpunkte
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSummary {
    pub block_height: u64,
    pub latest_hash: String,
    pub total_documents: u64,
    pub is_valid: bool,
}

/// Metriken-Snapshot für Monitoring-Endpunkt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterMetricsSnapshot {
    pub requests_total: u64,
    pub documents_uploaded: u64,
    pub documents_deleted: u64,
    pub sync_runs: u64,
    pub sync_success: u64,
    pub sync_failure: u64,
    pub ws_connections: u64,
    pub peers_total: u64,
    pub peers_healthy: u64,
    pub uptime_secs: u64,
    // Mining
    pub blocks_mined: u64,
    pub total_rewards_milli: u64,
    pub last_block_timestamp: u64,
    pub mining_throttle_pct: u64,
    pub chat_messages_mined: u64,
}

/// Anfrage zum Hinzufügen/Aktualisieren eines Dokuments über die API
#[derive(Debug, Deserialize)]
pub struct SubmitDocumentRequest {
    pub doc_id: Option<String>,
    pub title: String,
    pub content_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Anfrage zum Soft-Delete eines Dokuments
#[derive(Debug, Deserialize)]
pub struct DeleteDocumentRequest {
    pub doc_id: String,
}

/// Anfrage zum Hinzufügen eines Peers
#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub url: String,
    #[serde(default)]
    pub peer_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ca: Option<String>,
}

/// Antwort auf Block-Anfragen
#[derive(Debug, Serialize)]
pub struct BlockResponse {
    pub index: u64,
    pub timestamp: i64,
    pub hash: String,
    pub previous_hash: String,
    pub merkle_root: String,
    pub data_size: u64,
    pub owner: String,
    pub signer: String,
    pub documents: Vec<DocumentResponse>,
    pub tombstones_count: usize,
    pub node_role: String,
    pub validator_pub_key: String,
    pub validator_signature: String,
}

impl From<&crate::blockchain::Block> for BlockResponse {
    fn from(b: &crate::blockchain::Block) -> Self {
        BlockResponse {
            index: b.index,
            timestamp: b.timestamp,
            hash: b.hash.clone(),
            previous_hash: b.previous_hash.clone(),
            merkle_root: b.merkle_root.clone(),
            data_size: b.data_size,
            owner: b.owner.clone(),
            signer: b.signer.clone(),
            documents: b.documents.iter().map(DocumentResponse::from).collect(),
            tombstones_count: b.tombstones.len(),
            node_role: format!("{:?}", b.node_role),
            validator_pub_key: b.validator_pub_key.clone(),
            validator_signature: b.validator_signature.clone(),
        }
    }
}

/// Dokument-Antwort (ohne Chunk-Daten)
#[derive(Debug, Serialize)]
pub struct DocumentResponse {
    pub doc_id: String,
    pub title: String,
    pub content_type: String,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
    pub version: u32,
    pub size: u64,
    pub owner: String,
    pub updated_at: i64,
    pub chunks_count: usize,
}

impl From<&crate::blockchain::Document> for DocumentResponse {
    fn from(d: &crate::blockchain::Document) -> Self {
        // Korrigiere generische content_types anhand der Dateiendung im Titel
        let content_type = if d.content_type == "application/octet-stream" {
            guess_content_type_from_title(&d.title)
        } else {
            d.content_type.clone()
        };
        DocumentResponse {
            doc_id: d.doc_id.clone(),
            title: d.title.clone(),
            content_type,
            tags: d.tags.clone(),
            metadata: d.metadata.0.clone(),
            version: d.version,
            size: d.size,
            owner: d.owner.clone(),
            updated_at: d.updated_at,
            chunks_count: d.chunks.len(),
        }
    }
}

/// Leitet den MIME-Type aus dem Dateinamen ab (Extension-basiert).
fn guess_content_type_from_title(title: &str) -> String {
    let lower = title.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "pdf"              => "application/pdf",
        "doc"              => "application/msword",
        "docx"             => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls"              => "application/vnd.ms-excel",
        "xlsx"             => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "txt" | "log" | "md" | "csv" => "text/plain",
        "html" | "htm"     => "text/html",
        "json"             => "application/json",
        "xml"              => "application/xml",
        "png"              => "image/png",
        "jpg" | "jpeg"     => "image/jpeg",
        "gif"              => "image/gif",
        "svg"              => "image/svg+xml",
        "webp"             => "image/webp",
        "mp4"              => "video/mp4",
        "zip"              => "application/zip",
        _                  => "application/octet-stream",
    }
    .to_string()
}

/// Node-Status-Antwort für `/api/v1/status`
#[derive(Debug, Serialize)]
pub struct NodeStatusResponse {
    pub node_id: String,
    pub role: String,
    pub chain: ChainSummary,
    pub metrics: MasterMetricsSnapshot,
    pub peers: Vec<PeerInfo>,
    pub started_at: i64,
    pub trust: TrustSummary,
}

// ─── Web of Trust ─────────────────────────────────────────────────────────────

/// Status eines Trust-Eintrags
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustStatus {
    /// Antrag gestellt, Abstimmung läuft
    Pending,
    /// Mehrheitlich akzeptiert – Node ist vertrauenswürdig
    Active,
    /// Widerrufen durch Abstimmung
    Revoked,
}

/// Ein vertrauenswürdiger oder in Prüfung befindlicher Knoten
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    /// libp2p PeerId oder beliebige Node-Kennung
    pub peer_id: String,
    /// Ed25519 öffentlicher Schlüssel (hex)
    pub public_key_hex: String,
    /// Optionaler Anzeigename
    pub name: Option<String>,
    /// Status des Eintrags
    pub status: TrustStatus,
    /// Zustimmungen (peer_id der Voter)
    pub votes_approve: Vec<String>,
    /// Ablehnungen (peer_id der Voter)
    pub votes_reject: Vec<String>,
    /// Zeitpunkt des Join-Requests (Unix-Timestamp)
    pub requested_at: i64,
    /// Zeitpunkt der Statusänderung
    pub decided_at: Option<i64>,
}

impl TrustEntry {
    pub fn new(peer_id: String, public_key_hex: String, name: Option<String>) -> Self {
        Self {
            peer_id,
            public_key_hex,
            name,
            status: TrustStatus::Pending,
            votes_approve: Vec::new(),
            votes_reject: Vec::new(),
            requested_at: Utc::now().timestamp(),
            decided_at: None,
        }
    }
}

/// Einzelne Abstimmung (Audit-Log)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVote {
    pub voter_peer_id: String,
    pub target_peer_id: String,
    pub approve: bool,
    pub timestamp: i64,
}

/// Kompakte Trust-Zusammenfassung für NodeStatusResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSummary {
    pub active: usize,
    pub pending: usize,
    pub revoked: usize,
}
