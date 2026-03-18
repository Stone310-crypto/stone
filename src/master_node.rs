//! Master Node – Koordinations- und Konsensus-Schicht
//!
//! Die Master Node ist der zentrale Koordinator des Stone-Clusters.
//! Sie verwaltet den Cluster-State, koordiniert Peer-Synchronisation,
//! und stellt die API-Schicht für die externe Web-UI bereit.
//!
//! ## Block-Mining (Interval-Mining)
//!
//! Alle `MINING_INTERVAL_SECS` Sekunden erstellt der ausgewählte PoA-Validator
//! einen neuen Block — auch wenn keine Dokumente vorliegen. Jeder Block enthält:
//! - Alle pending Mempool-TXs
//! - Eine System-Reward-TX (`TxType::Reward`) an den Validator
//! - Optional: Dokumente (werden weiterhin über Upload-Handler hinzugefügt)
//!
//! Der Block-Reward folgt einem **Halving-Schema**: alle `HALVING_INTERVAL`
//! Blöcke halbiert sich der Reward. Mining stoppt wenn `pool:storage_rewards` leer ist.

use crate::blockchain::{Block, Document, DocumentTombstone, NodeRole, StoneChain};
use crate::consensus::{
    load_or_create_validator_key, local_validator_pubkey_hex, sign_block,
    CheckpointStore, EquivocationTracker, SlashingStore,
    ValidatorSet, VotingRound,
};
use crate::shard::ShardHolderRegistry;
use crate::chat_policy::ChatPolicyStore;
use crate::token::{Mempool, TokenLedger, ReputationRegistry};
use crate::token::transaction::{TokenTx, TxType, compute_tx_id};
use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

// ─── Mining-Konstanten ───────────────────────────────────────────────────────

/// Ziel-Block-Zeit in Sekunden (Competitive PoW).
/// 30s = schnelle Blöcke, Difficulty wird dynamisch angepasst.
pub const TARGET_BLOCK_TIME_SECS: u64 = crate::consensus::TARGET_BLOCK_TIME_SECS;

/// Legacy: Block-Intervall in Sekunden (für Kompatibilität mit altem Code).
/// Wird durch TARGET_BLOCK_TIME_SECS ersetzt.
pub const MINING_INTERVAL_SECS: u64 = TARGET_BLOCK_TIME_SECS;

/// Initialer Block-Reward in STONE (vor erstem Halving)
pub const INITIAL_BLOCK_REWARD: &str = "10.0";

/// Alle N Blöcke halbiert sich der Reward
/// 210.000 Blöcke × 30s = ~73 Tage pro Halving-Epoche
pub const HALVING_INTERVAL: u64 = 210_000;

/// Maximale Supply (aus Genesis-Config, hier als Fallback)
pub const MAX_SUPPLY: &str = "50000000";

/// Minimaler Block-Reward (unter diesem Wert wird nicht mehr gemined)
pub const MIN_BLOCK_REWARD: &str = "0.00000001";

/// Timeout für Peer-Voting in Sekunden (Multi-Node-Konsensus)
pub const VOTE_TIMEOUT_SECS: u64 = 10;

/// Wie oft (Sekunden) ein neues Mining-Template generiert wird.
/// Externe Miner können das Template per API abrufen.
pub const TEMPLATE_REFRESH_SECS: u64 = 5;

// ─── Mining Template ─────────────────────────────────────────────────────────

/// Block-Template für externe Miner.
/// Enthält alle Daten die ein Miner braucht um einen Block zu lösen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningTemplate {
    /// Block-Index (Höhe)
    pub block_index: u64,
    /// Hash des Vorgänger-Blocks
    pub previous_hash: String,
    /// Aktuelle Argon2id-PoW-Difficulty (Netzwerk-Basis, Anzahl führender Null-Bits)
    pub difficulty: u32,
    /// Effektive Difficulty nach Stake-Bonus (PoS/PoW Hybrid).
    /// <= difficulty. Miner löst gegen diesen (leichteren) Target.
    #[serde(default)]
    pub effective_difficulty: u32,
    /// Unix-Timestamp wann das Template erstellt wurde
    pub timestamp: i64,
    /// Validator-Public-Key (wird für PoW-Input benötigt)
    pub validator_pubkey: String,
    /// SHA-256 Hash des vorbereiteten Blocks (ohne PoW-Felder)
    /// Der Miner muss den PoW über prev_hash, block_index, validator_pubkey lösen.
    pub block_hash_pre_pow: String,
    /// Anzahl Transaktionen im Block
    pub tx_count: usize,
    /// Block-Reward in STONE
    pub reward: String,
    /// Template-ID (für Submit-Zuordnung)
    pub template_id: String,
}

/// Einreichung eines gelösten Blocks durch einen externen Miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningSubmission {
    /// Template-ID (muss mit dem aktuellen Template übereinstimmen)
    pub template_id: String,
    /// Gelöster PoW-Nonce
    pub nonce: u64,
    /// Argon2id-Hash (hex-encoded)
    pub pow_hash: String,
}

// ─── Peer-Status ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerStatus {
    /// Erreichbar, Chain in Sync
    Healthy,
    /// Erreichbar, aber Chain divergiert
    Diverged,
    /// Nicht erreichbar
    Unreachable,
    /// Quarantäne (Integritätsfehler)
    Quarantined,
}

impl Default for PeerStatus {
    fn default() -> Self {
        PeerStatus::Unreachable
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub url: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ca: Option<String>,
    #[serde(default)]
    pub status: PeerStatus,
    #[serde(default)]
    pub last_seen: i64,
    #[serde(default)]
    pub last_hash: Option<String>,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub latency_ms: Option<u128>,
    #[serde(default)]
    pub sync_failures: u32,
}

impl PeerInfo {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            name: None,
            ca: None,
            status: PeerStatus::Unreachable,
            last_seen: 0,
            last_hash: None,
            block_height: 0,
            latency_ms: None,
            sync_failures: 0,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.status == PeerStatus::Healthy
    }

    pub fn mark_healthy(&mut self, hash: String, height: u64, latency_ms: u128) {
        self.status = PeerStatus::Healthy;
        self.last_seen = Utc::now().timestamp();
        self.last_hash = Some(hash);
        self.block_height = height;
        self.latency_ms = Some(latency_ms);
        self.sync_failures = 0;
    }

    pub fn mark_unreachable(&mut self) {
        self.status = PeerStatus::Unreachable;
        self.sync_failures += 1;
    }

    pub fn mark_diverged(&mut self, peer_hash: String, peer_height: u64) {
        self.status = PeerStatus::Diverged;
        self.last_seen = Utc::now().timestamp();
        self.last_hash = Some(peer_hash);
        self.block_height = peer_height;
    }
}

// ─── Konsensus-Runde ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRound {
    pub round: u64,
    pub proposed_hash: String,
    pub votes: HashMap<String, bool>,
    pub started_at: i64,
    pub finalized: bool,
}

impl ConsensusRound {
    pub fn new(round: u64, proposed_hash: String) -> Self {
        Self {
            round,
            proposed_hash,
            votes: HashMap::new(),
            started_at: Utc::now().timestamp(),
            finalized: false,
        }
    }

    /// Stimme eines Peers registrieren (url → accept)
    pub fn vote(&mut self, peer_url: String, accept: bool) {
        self.votes.insert(peer_url, accept);
    }

    /// Einfache Mehrheit: mehr als 50% aller abgegebenen Stimmen = accept
    pub fn quorum_reached(&self, total_peers: usize) -> bool {
        let accepts = self.votes.values().filter(|&&v| v).count();
        let needed = (total_peers / 2) + 1;
        accepts >= needed
    }
}

// ─── Master Node Events (für WebSocket-Broadcast) ────────────────────────────

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

// ─── Master Node State ───────────────────────────────────────────────────────

/// Globaler State der Master Node.
/// Wird als `Arc<MasterNodeState>` durch den gesamten Server geteilt.
pub struct MasterNodeState {
    /// Eindeutige Node-ID (z.B. Hostname oder UUID)
    pub node_id: String,
    /// Rolle dieser Node im Cluster
    pub role: NodeRole,
    /// Cluster-Schlüssel für HMAC-Signierung
    pub cluster_key: String,
    /// Die Blockchain
    pub chain: Arc<Mutex<StoneChain>>,
    /// Bekannte Peers
    pub peers: RwLock<Vec<PeerInfo>>,
    /// Aktive Konsensus-Runde (falls vorhanden)
    pub consensus: Mutex<Option<ConsensusRound>>,
    /// PoA Validator-Whitelist
    pub validator_set: RwLock<ValidatorSet>,
    /// Aktive PoA Voting-Runde (falls vorhanden)
    pub active_voting: Mutex<Option<VotingRound>>,
    /// Monoton ansteigender Runden-Zähler
    pub round_counter: AtomicU64,
    /// Event-Bus für WebSocket-Broadcasts
    pub events: EventBus,
    /// Counters für Metriken
    pub metrics: MasterMetrics,
    /// Zeitpunkt des Starts
    pub started_at: i64,
    /// Web-of-Trust Registry
    pub trust_registry: RwLock<Vec<TrustEntry>>,
    /// Abstimmungshistorie (Audit-Log)
    pub trust_history: Mutex<Vec<TrustVote>>,
    /// StoneCoin Token-Ledger (Account-Balancen, Nonces)
    pub token_ledger: RwLock<TokenLedger>,
    /// StoneCoin Mempool (pending Transaktionen)
    pub mempool: Mempool,
    /// Off-Chain Message Pool für Chat-Nachrichten (Batch-Commits statt Einzel-TXs)
    pub message_pool: crate::message_pool::MessagePool,
    /// StoneCoin Staking-Pool
    pub staking_pool: RwLock<crate::token::StakingPool>,
    /// Shard-Holder-Registry: Wer hält welchen Shard?
    pub shard_registry: ShardHolderRegistry,
    /// Finality Checkpoints (unwiderrufliche Chain-Punkte)
    pub checkpoint_store: RwLock<CheckpointStore>,
    /// Slashing-Store (Strafen, Jail-Status, Downtime-Tracker)
    pub slashing_store: RwLock<SlashingStore>,
    /// Reputation-Registry (Node-Reputation + Fee-Share-Verteilung)
    pub reputation_registry: RwLock<ReputationRegistry>,
    /// Chat-Policy Store (Self-Destruct TTL, Reports, Stake-Gate)
    pub chat_policy: RwLock<ChatPolicyStore>,
    /// Gebundene Mining-Reward-Wallet (Account-gebunden).
    /// Falls gesetzt, gehen alle Block-Rewards an diese Wallet statt an die Validator-Wallet.
    /// Wird in `stone_data/mining_config.json` persistiert.
    pub mining_wallet: RwLock<Option<String>>,
    /// Pending ChallengeResponses: Nodes schicken ihre Proofs hierher,
    /// werden im nächsten Block aufgenommen und belohnt.
    pub pending_challenge_responses: Mutex<Vec<crate::storage_proof::ChallengeResponse>>,
    /// Pending Shard-Repair-Rewards: Miner melden reparierte Shards,
    /// werden im nächsten Block als Reward-TX aufgenommen.
    pub pending_repair_rewards: Mutex<Vec<crate::storage_proof::RepairReward>>,
    /// Kanal um geminete Blöcke an das P2P-Netzwerk zu broadcasten.
    /// Wird von setup.rs gesetzt nachdem das Netzwerk gestartet ist.
    pub block_broadcast_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Block>>>,
    /// Equivocation-Tracker: Erkennt Double-Signing durch Validatoren
    pub equivocation_tracker: Mutex<EquivocationTracker>,
    /// Aktuelles Mining-Template (für externe Miner).
    /// Enthält einen vorbereiteten Block ohne PoW-Lösung.
    pub current_mining_template: RwLock<Option<(MiningTemplate, Block)>>,
}

#[derive(Default)]
pub struct MasterMetrics {
    pub requests_total: AtomicU64,
    pub documents_uploaded: AtomicU64,
    pub documents_deleted: AtomicU64,
    pub sync_runs: AtomicU64,
    pub sync_success: AtomicU64,
    pub sync_failure: AtomicU64,
    pub ws_connections: AtomicU64,
    // ── Mining-Metriken ──────────────────────────────────
    /// Anzahl der erfolgreich geminten Blöcke seit Node-Start
    pub blocks_mined: AtomicU64,
    /// Gesamte Rewards die diese Node erhalten hat (in Milli-STONE * 1000, als u64 kodiert)
    pub total_rewards_milli: AtomicU64,
    /// Timestamp des letzten geminten Blocks (Unix-Secs)
    pub last_block_timestamp: AtomicU64,
    /// Mining-Leistungsbegrenzung in Prozent (0-100, 0=aus, 100=volle Leistung)
    /// Default: 100 (keine Begrenzung)
    pub mining_throttle_pct: AtomicU64,
    /// Anzahl der Chat-Nachrichten die geminet wurden
    pub chat_messages_mined: AtomicU64,
    /// Initialer Peer-Sync abgeschlossen (Mining erst danach starten)
    pub initial_sync_done: AtomicBool,
    /// Sync-Fortschritt: Chain-Höhe zu Beginn des aktuellen Syncs
    pub syncing_from_height: AtomicU64,
    /// Sync-Fortschritt: Ziel-Chain-Höhe des aktuellen Syncs (0 = kein Sync aktiv)
    pub syncing_to_height: AtomicU64,
}

impl MasterNodeState {
    pub fn new(node_id: String, cluster_key: String, role: NodeRole) -> Arc<Self> {
        let chain = StoneChain::load_or_create(&cluster_key);

        // Token-Ledger laden oder aus Chain rekonstruieren
        let mut ledger = TokenLedger::load();

        // ── Einmalige Migration: ChatMessage-Nonce-Fix ──
        // Älterer Code hat advance_nonce() auch für ChatMessage-TXs aufgerufen,
        // was zu aufgeblähten Nonces führte und Transfer-TXs blockierte.
        // Ein einmaliger Rebuild aus der Chain korrigiert alle Nonces.
        {
            let needs_migration = {
                let db = crate::token::open_token_db();
                db.map(|d| d.get(b"__mig_chatmsg_nonce_v1").ok().flatten().is_none())
                    .unwrap_or(false)
            };
            if needs_migration && !chain.blocks.is_empty() {
                println!("[token] 🔄 Nonce-Migration: Ledger wird aus Chain neu aufgebaut …");
                ledger = TokenLedger::rebuild_from_chain(&chain.blocks);
                if let Err(e) = ledger.persist() {
                    eprintln!("[token] ⚠️  Persist nach Migration fehlgeschlagen: {e}");
                }
                if let Ok(db) = crate::token::open_token_db() {
                    let _ = db.put(b"__mig_chatmsg_nonce_v1", b"done");
                }
                println!("[token] ✅ Nonce-Migration abgeschlossen");
            }
        }

        // ── Einmalige Nonce-Repair-Migration (v2): Erzwingt Rebuild ────
        // VPS-Nodes können nach Reorgs falsche Nonces/Balancen haben.
        // v2 hat bei frischen Nodes nicht gegriffen (Chain war leer beim Start).
        // v3: Erzwingt rebuild_from_chain wenn Chain vorhanden, sonst setzt
        // last_synced_block zurück damit sync_with_chain einen Rebuild triggert.
        {
            let needs_repair = {
                let db = crate::token::open_token_db();
                db.map(|d| d.get(b"__mig_ledger_repair_v3").ok().flatten().is_none())
                    .unwrap_or(false)
            };
            if needs_repair {
                if chain.blocks.len() > 1 {
                    // Chain hat Daten → sofort rebuilden
                    println!("[token] 🔄 Ledger-Repair v3: Rebuild aus {} Chain-Blöcken …", chain.blocks.len());
                    ledger = TokenLedger::rebuild_from_chain(&chain.blocks);
                    if let Err(e) = ledger.persist() {
                        eprintln!("[token] ⚠️  Persist nach Repair v3 fehlgeschlagen: {e}");
                    }
                    println!("[token] ✅ Ledger-Repair v3 abgeschlossen");
                } else {
                    // Chain leer (frische Node) → last_synced_block zurücksetzen
                    // damit sync_with_chain nach dem p2p-Sync einen verify_and_repair triggert
                    println!("[token] 🔄 Ledger-Repair v3: Chain leer, setze Sync-Marker zurück");
                    ledger.reset_sync_marker();
                    let _ = ledger.persist();
                }
                if let Ok(db) = crate::token::open_token_db() {
                    let _ = db.put(b"__mig_ledger_repair_v3", b"done");
                }
            }
        }
        if ledger.total_supply() == rust_decimal::Decimal::ZERO && chain.blocks.len() > 0 {
            // Versuche Rebuild aus Chain (falls DB fehlt, aber Chain TXs hat)
            ledger = TokenLedger::rebuild_from_chain(&chain.blocks);
        } else if !chain.blocks.is_empty() {
            // Sync-Check: vergleiche DB-Stand mit Chain und repariere bei Desync
            ledger.sync_with_chain(&chain.blocks);
        }
        if ledger.total_supply() == rust_decimal::Decimal::ZERO {
            // Erster Start: Genesis-Allokation anwenden
            match crate::token::apply_genesis(&mut ledger) {
                Ok(txs) => {
                    if !txs.is_empty() {
                        println!("[token] Genesis: {} Mint-TXs erstellt", txs.len());
                    }
                }
                Err(e) => eprintln!("[token] ⚠️  Genesis-Fehler: {e}"),
            }
        }

        let started_at = Utc::now().timestamp();
        let mut staking_pool = crate::token::StakingPool::load();
        // Pool-Konsistenz prüfen: Wenn der Pool leer ist oder total_staked
        // von der tatsächlichen pool:staking-Balance im Ledger abweicht,
        // den Pool aus der Chain-History komplett neu aufbauen.
        if !chain.blocks.is_empty() {
            let pool_balance = ledger.balance(crate::token::staking::STAKING_POOL_ADDRESS);
            if staking_pool.stakers.is_empty() || staking_pool.total_staked != pool_balance {
                if staking_pool.total_staked != pool_balance {
                    println!(
                        "[staking] ⚠️  Pool-Desync: total_staked={}, pool:staking-Balance={} → Rebuild",
                        staking_pool.total_staked, pool_balance,
                    );
                }
                staking_pool = crate::token::StakingPool::rebuild_from_chain(&chain.blocks);
            }
        }
        let reputation_registry = ReputationRegistry::load();
        let chat_policy = ChatPolicyStore::load();
        let state = Arc::new(Self {
            node_id: node_id.clone(),
            role,
            cluster_key,
            chain: Arc::new(Mutex::new(chain)),
            peers: RwLock::new(Vec::new()),
            consensus: Mutex::new(None),
            validator_set: RwLock::new(ValidatorSet::load()),
            active_voting: Mutex::new(None),
            round_counter: AtomicU64::new(1),
            events: EventBus::new(256),
            metrics: {
                let m = MasterMetrics::default();
                // STONE_MINING_THROTTLE env var (0-100, default 100)
                let initial_throttle: u64 = std::env::var("STONE_MINING_THROTTLE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100)
                    .min(100);
                m.mining_throttle_pct.store(initial_throttle, Ordering::Relaxed);
                if initial_throttle < 100 {
                    println!("[mining] ⚠ Initiale Throttle via STONE_MINING_THROTTLE: {initial_throttle}%");
                }
                m
            },
            started_at,
            trust_registry: RwLock::new(Vec::new()),
            trust_history: Mutex::new(Vec::new()),
            token_ledger: RwLock::new(ledger),
            mempool: Mempool::new(),
            message_pool: crate::message_pool::MessagePool::load(),
            staking_pool: RwLock::new(staking_pool),
            shard_registry: ShardHolderRegistry::new(),
            checkpoint_store: RwLock::new(CheckpointStore::load()),
            slashing_store: RwLock::new(SlashingStore::load()),
            reputation_registry: RwLock::new(reputation_registry),
            chat_policy: RwLock::new(chat_policy),
            mining_wallet: RwLock::new(Self::load_mining_wallet()),
            pending_challenge_responses: Mutex::new(Vec::new()),
            pending_repair_rewards: Mutex::new(Vec::new()),
            block_broadcast_tx: Mutex::new(None),
            equivocation_tracker: Mutex::new(EquivocationTracker::new()),
            current_mining_template: RwLock::new(None),
        });

        // Nach Restart: Prüfen ob die lokale Chain aktuell genug ist.
        // Wenn der letzte Block jünger als 3 Mining-Intervalle (6 Min) ist,
        // war die Node erst kürzlich online und kann sofort minen.
        // Ansonsten: Initial-Sync abwarten (max 240s), damit wir nicht
        // auf einem veralteten Fork minen.
        {
            let chain = state.chain.lock().unwrap();
            let chain_len = chain.blocks.len();
            let last_block_age = chain.blocks.last()
                .map(|b| {
                    let now = Utc::now().timestamp();
                    (now - b.timestamp).max(0) as u64
                })
                .unwrap_or(u64::MAX);
            drop(chain);

            let max_age = MINING_INTERVAL_SECS * 3; // 6 Minuten
            if chain_len > 1 && last_block_age < max_age {
                // Chain ist aktuell — Node war kürzlich online, kein Sync nötig
                state.metrics.initial_sync_done.store(true, Ordering::Relaxed);
                println!(
                    "[mining] Chain hat {chain_len} Blöcke, letzter Block vor {last_block_age}s – Initial-Sync übersprungen"
                );
            } else if chain_len <= 1 {
                println!(
                    "[mining] Frische Node (nur Genesis) – warte auf Initial-Sync (max {}s)",
                    MINING_INTERVAL_SECS * 2
                );
            } else {
                println!(
                    "[mining] Chain hat {chain_len} Blöcke, letzter Block vor {last_block_age}s – warte auf Initial-Sync (max {}s)",
                    MINING_INTERVAL_SECS * 2
                );
            }
        }

        // Node-gestartet Event senden
        state.events.publish(NodeEvent::NodeStarted {
            node_id: node_id.clone(),
            role: "master".into(),
            timestamp: started_at,
        });

        // ── Auto-Register: Node als Validator registrieren ───────────────
        {
            let signing_key = load_or_create_validator_key();
            let pub_key_hex = local_validator_pubkey_hex(&signing_key);
            let mut vs = state.validator_set.write().unwrap();
            if vs.get(&node_id).is_none() {
                use crate::consensus::ValidatorInfo;
                // Erster Node im Netzwerk → sofort aktiv (Bootstrap).
                // Weitere Nodes → pending (müssen erst aktiviert werden).
                if vs.validators.is_empty() {
                    let info = ValidatorInfo::new(node_id.clone(), pub_key_hex.clone());
                    vs.add(info);
                    println!(
                        "[consensus] ✅ Bootstrap-Node '{}' als aktiver Validator registriert (Wallet: {}…)",
                        &node_id,
                        &pub_key_hex[..16.min(pub_key_hex.len())]
                    );
                } else {
                    let info = ValidatorInfo::new_pending(node_id.clone(), pub_key_hex.clone());
                    vs.add(info);
                    println!(
                        "[consensus] ⏳ Node '{}' als PENDING Validator registriert – Aktivierung durch Admin oder Stake erforderlich (Wallet: {}…)",
                        &node_id,
                        &pub_key_hex[..16.min(pub_key_hex.len())]
                    );
                }
            } else {
                // Key-Rotation erkennen: Wenn sich der lokale Validator-Key geändert hat,
                // muss der Public Key im ValidatorSet aktualisiert werden.
                let existing_pk = vs.get(&node_id).map(|v| v.public_key_hex.clone()).unwrap_or_default();
                if existing_pk != pub_key_hex {
                    eprintln!(
                        "[consensus] ⚠️  Validator-Key hat sich geändert! Alter Key: {}…, Neuer Key: {}…",
                        &existing_pk[..16.min(existing_pk.len())],
                        &pub_key_hex[..16.min(pub_key_hex.len())],
                    );
                    if let Some(v) = vs.validators.iter_mut().find(|v| v.node_id == node_id) {
                        v.public_key_hex = pub_key_hex.clone();
                    }
                    vs.save();
                    println!(
                        "[consensus] 🔄 Public Key für '{}' aktualisiert → {}…",
                        &node_id,
                        &pub_key_hex[..16.min(pub_key_hex.len())],
                    );
                } else {
                    println!(
                        "[consensus] Validator '{}' bereits registriert",
                        &node_id
                    );
                }
            }
        }

        // ── Validator Auto-Discovery aus bestehender Chain ───────────────
        // Beim Start: Nur aus den LETZTEN 20 Block-Signern Validatoren
        // registrieren. Verhindert dass tote Nodes aus alten Blöcken
        // die Validator-Rotation stören.
        {
            let chain = state.chain.lock().unwrap();
            let mut vs = state.validator_set.write().unwrap();
            let mut discovered = 0u32;
            let start = chain.blocks.len().saturating_sub(20);
            for block in &chain.blocks[start..] {
                if !block.signer.is_empty()
                    && !block.validator_pub_key.is_empty()
                    && block.signer != node_id
                    && vs.get(&block.signer).is_none()
                {
                    use crate::consensus::ValidatorInfo;
                    // Auto-discovered Nodes starten als pending –
                    // sie müssen ihre Aktivität erst beweisen.
                    let info = ValidatorInfo::new_pending(
                        block.signer.clone(),
                        block.validator_pub_key.clone(),
                    );
                    vs.add(info);
                    discovered += 1;
                }
            }
            if discovered > 0 {
                println!(
                    "[consensus] 🔗 {} Validator(en) aus letzten {} Blöcken auto-discovered (gesamt: {})",
                    discovered, chain.blocks.len().min(20), vs.active_count()
                );
            }
        }

        state
    }

    /// Baut die drei Maps die für stake-gewichtete Validator-Auswahl benötigt werden:
    /// 1. `stakes`: wallet_address → gestakter Betrag
    /// 2. `jailed`: Set von Validator-IDs die gejailed sind
    /// 3. `wallet_map`: node_id → wallet_address (soweit bekannt)
    pub fn build_selection_context(&self) -> (
        HashMap<String, rust_decimal::Decimal>,
        std::collections::HashSet<String>,
        HashMap<String, String>,
    ) {
        // Stakes aus StakingPool
        let stakes: HashMap<String, rust_decimal::Decimal> = {
            let pool = self.staking_pool.read().unwrap();
            pool.stakers.iter()
                .map(|(addr, entry)| (addr.clone(), entry.staked_amount))
                .collect()
        };

        // Jailed aus SlashingStore
        let jailed: std::collections::HashSet<String> = {
            let ss = self.slashing_store.read().unwrap();
            ss.jailed.keys().cloned().collect()
        };

        // Wallet-Map: Alle bekannten Validatoren → public_key_hex als Wallet
        let mut wallet_map = HashMap::new();
        {
            let vs = self.validator_set.read().unwrap();
            for v in &vs.validators {
                if v.active && !v.public_key_hex.is_empty() {
                    wallet_map.insert(v.node_id.clone(), v.public_key_hex.clone());
                }
            }
        }
        // Explizite ENV-Variable hat Vorrang (für Custom-Wallet-Setup)
        if let Ok(wallet) = std::env::var("STONE_NODE_WALLET") {
            wallet_map.insert(self.node_id.clone(), wallet);
        }

        (stakes, jailed, wallet_map)
    }

    /// Dokumente zur Blockchain hinzufügen und Event publizieren.
    ///
    /// PoA prüft die **Node-ID** (`self.node_id`), nicht den User/Signer.
    /// User sind Dokument-Owner — die Node ist der Validator.
    /// Wenn PoA aktiv ist (ValidatorSet nicht leer):
    ///   - Prüft ob diese Node ein aktiver Validator ist → Err falls nicht
    ///   - Signiert den Block-Hash mit dem lokalen Validator-Schlüssel
    ///   - Setzt `validator_pub_key` und `validator_signature` im Block
    pub fn commit_documents(
        &self,
        documents: Vec<Document>,
        tombstones: Vec<DocumentTombstone>,
        owner: String,
        signer: String,
    ) -> Result<Block, String> {
        // ── Lock-Ordnung: chain → ledger → (drop) → validator_set ────────
        //
        // WICHTIG: validator_set.write() darf NICHT gehalten werden während
        // chain.lock() gehalten wird, da prepare_mining_block() in umgekehrter
        // Reihenfolge lockt (validator_set.read → chain.lock → drop chain → ...).
        // Deshalb: chain/ledger-Arbeit zuerst, dann validator_set-Updates.

        // PoA: Validator-Prüfung auf Node-Ebene (nicht User-Ebene)
        //
        // v0.5.0: Stake-gewichtete Validator-Rotation
        // Validatoren mit mehr Stake haben proportional höhere Chance,
        // gejailte Validatoren werden übersprungen.
        //
        // Schritt 1: Chain-Daten holen (eigener Scope → chain wird gedroppt)
        let (next_index, prev_hash_owned) = {
            let chain = self.chain.lock().unwrap();
            let idx = chain.blocks.len() as u64;
            let hash = chain.blocks.last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".into());
            (idx, hash)
        };
        // Schritt 2: Validator-Prüfung (chain NICHT gehalten)
        let should_sign = {
            let vs = self.validator_set.read().unwrap();
            if !vs.validators.is_empty() {
                if !vs.is_active_validator(&self.node_id) {
                    return Err(format!(
                        "PoA: Diese Node ('{}') ist kein aktiver Validator. \
                         Bitte Node als Validator registrieren.",
                        self.node_id
                    ));
                }
                let (stakes, jailed, wallet_map) = self.build_selection_context();
                if !vs.is_selected_validator_weighted(&self.node_id, &prev_hash_owned, next_index, &stakes, &jailed, &wallet_map) {
                    let selected = vs.select_validator_weighted(&prev_hash_owned, next_index, &stakes, &jailed, &wallet_map)
                        .map(|v| v.node_id.clone())
                        .unwrap_or_else(|| "?".into());
                    return Err(format!(
                        "PoA: Diese Node ('{}') ist nicht der ausgewählte Validator für Block #{}. \
                         Ausgewählt: '{}'.",
                        self.node_id, next_index, selected
                    ));
                }
                true
            } else {
                false
            }
        };

        // ── Mempool: Pending TXs für diesen Block entnehmen ──────────────────
        let mut pending_txs = self.mempool.drain_for_block();
        let standard_txs = self.mempool.drain_standard_txs();
        pending_txs.extend(standard_txs);

        // ── Chain + Ledger + Signierung (chain gelockt) ──────────────────────
        let block = {
            let mut chain = self.chain.lock().unwrap();
            let mut block = chain.add_documents(
                documents.clone(),
                tombstones.clone(),
                pending_txs,
                owner.clone(),
                signer.clone(),
                &self.cluster_key,
                self.role.clone(),
            );

            // Token-TXs im Ledger verarbeiten (chain → ledger: korrekte Reihenfolge)
            if !block.transactions.is_empty() {
                let mut ledger = self.token_ledger.write().unwrap();
                let receipts = ledger.apply_block_txs(&block.transactions, block.index);
                if !receipts.is_empty() {
                    if let Err(e) = ledger.persist() {
                        eprintln!("[token] Ledger-Persistierung nach Block #{} fehlgeschlagen: {e}", block.index);
                    }
                }
            }

            // PoA: Block-Signierung (kein vs-Lock nötig, nur cached Key)
            if should_sign {
                let signing_key = load_or_create_validator_key();
                let pub_key_hex = local_validator_pubkey_hex(&signing_key);
                let sig = sign_block(&signing_key, &block.hash);
                block.validator_pub_key = pub_key_hex;
                block.validator_signature = sig;

                // Signierter Block in RocksDB aktualisieren (mit WAL-Sync)
                use crate::storage::ChainStore;
                if let Ok(store) = ChainStore::open() {
                    let _ = store.write_block_sync(&block);
                }
                // In-memory chain aktualisieren
                if let Some(last) = chain.blocks.last_mut() {
                    last.validator_pub_key = block.validator_pub_key.clone();
                    last.validator_signature = block.validator_signature.clone();
                }
            }

            block
        }; // ← chain wird hier gedroppt

        // ── Validator-Statistik aktualisieren (chain NICHT gehalten) ─────────
        if should_sign {
            let mut vs_w = self.validator_set.write().unwrap();
            if let Some(v) = vs_w.get_mut(&self.node_id) {
                v.blocks_signed += 1;
                vs_w.save();
            }
        }

        // Events publizieren
        self.events.publish(NodeEvent::BlockAdded {
            index: block.index,
            hash: block.hash.clone(),
            docs: block.documents.len(),
            owner: block.owner.clone(),
            timestamp: block.timestamp,
        });

        for doc in &block.documents {
            self.events.publish(NodeEvent::DocumentUpdated {
                doc_id: doc.doc_id.clone(),
                title: doc.title.clone(),
                owner: doc.owner.clone(),
                version: doc.version,
                block_index: block.index,
            });
            self.metrics.documents_uploaded.fetch_add(1, Ordering::Relaxed);
        }

        for ts in &block.tombstones {
            self.events.publish(NodeEvent::DocumentDeleted {
                doc_id: ts.doc_id.clone(),
                owner: ts.owner.clone(),
                block_index: block.index,
            });
            self.metrics.documents_deleted.fetch_add(1, Ordering::Relaxed);
        }

        // Token-TX Events für WebSocket
        for tx in &block.transactions {
            self.events.publish(NodeEvent::TokenTransfer {
                tx_id: tx.tx_id.clone(),
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount: tx.amount.to_string(),
                tx_type: tx.tx_type.to_string(),
                block_index: block.index,
            });
        }

        Ok(block)
    }

    /// Peer hinzufügen oder aktualisieren
    pub fn upsert_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.write().unwrap();
        if let Some(existing) = peers.iter_mut().find(|p| p.url == peer.url) {
            *existing = peer;
        } else {
            peers.push(peer);
        }
    }

    /// Peer-Status aktualisieren
    pub fn set_peer_status(&self, url: &str, status: PeerStatus) {
        let mut peers = self.peers.write().unwrap();
        if let Some(p) = peers.iter_mut().find(|p| p.url == url) {
            let changed = p.status != status;
            p.status = status.clone();
            if changed {
                self.events.publish(NodeEvent::PeerStatusChanged {
                    url: url.to_string(),
                    status,
                });
            }
        }
    }

    /// Alle Peers entfernen und neu setzen
    pub fn replace_peers(&self, peers: Vec<PeerInfo>) {
        let mut locked = self.peers.write().unwrap();
        *locked = peers;
    }
    /// Statische Hilfsfunktion: PeerInfo-Objekt direkt als UNREACHABLE markieren.
    pub fn mark_peer_unhealthy(peer: &mut PeerInfo) {
        if peer.status != PeerStatus::Unreachable {
            peer.mark_unreachable();
            println!(
                "[network] ⚠️  Peer '{}' markiert als UNREACHABLE ({} Sync-Fehler)",
                peer.url, peer.sync_failures
            );
        }
    }

    /// Instanz-Methode: Peer per URL als UNREACHABLE markieren.
    /// Löst ein PeerStatusChanged-Event aus wenn sich der Status ändert.
    pub fn mark_peer_unhealthy_by_url(&self, url: &str) {
        self.set_peer_status(url, PeerStatus::Unreachable);
        let mut peers = self.peers.write().unwrap();
        if let Some(p) = peers.iter_mut().find(|p| p.url == url) {
            p.sync_failures = p.sync_failures.saturating_add(1);
        }
    }

    /// Peers lesen
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().unwrap().clone()
    }

    /// Staking-TXs aus einem Block im StakingPool verarbeiten + persistieren.
    /// Wird von allen Block-Ingestion-Pfaden aufgerufen (lokal, P2P, RangeSync).
    pub fn apply_staking_from_txs(&self, txs: &[crate::token::TokenTx]) {
        use crate::token::TxType;
        let mut pool = self.staking_pool.write().unwrap();
        let mut changed = false;
        for tx in txs {
            match tx.tx_type {
                TxType::Stake => {
                    if let Err(e) = pool.stake(&tx.from, tx.amount) {
                        eprintln!("[staking] Stake fehlgeschlagen für {}: {e}", &tx.from[..12.min(tx.from.len())]);
                    } else {
                        changed = true;
                    }
                }
                TxType::Unstake => {
                    if let Err(e) = pool.request_unstake(&tx.from, tx.amount) {
                        eprintln!("[staking] Unstake fehlgeschlagen für {}: {e}", &tx.from[..12.min(tx.from.len())]);
                    } else {
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        if changed {
            if let Err(e) = pool.persist() {
                eprintln!("[staking] Pool-Persist fehlgeschlagen: {e}");
            }
        }
    }

    /// Chain-Zusammenfassung für API-Antworten
    pub fn chain_summary(&self) -> ChainSummary {
        let chain = self.chain.lock().unwrap();
        let total_docs: usize = chain
            .list_all_documents()
            .len();
        ChainSummary {
            block_height: chain.blocks.len() as u64,
            latest_hash: chain.latest_hash.clone(),
            total_documents: total_docs as u64,
            is_valid: chain.verify(&self.cluster_key),
        }
    }

    /// Metriken für API
    pub fn snapshot_metrics(&self) -> MasterMetricsSnapshot {
        let peers = self.peers.read().unwrap();
        let healthy = peers.iter().filter(|p| p.is_healthy()).count();
        MasterMetricsSnapshot {
            requests_total: self.metrics.requests_total.load(Ordering::Relaxed),
            documents_uploaded: self.metrics.documents_uploaded.load(Ordering::Relaxed),
            documents_deleted: self.metrics.documents_deleted.load(Ordering::Relaxed),
            sync_runs: self.metrics.sync_runs.load(Ordering::Relaxed),
            sync_success: self.metrics.sync_success.load(Ordering::Relaxed),
            sync_failure: self.metrics.sync_failure.load(Ordering::Relaxed),
            ws_connections: self.metrics.ws_connections.load(Ordering::Relaxed),
            peers_total: peers.len() as u64,
            peers_healthy: healthy as u64,
            uptime_secs: (Utc::now().timestamp() - self.started_at) as u64,
            blocks_mined: self.metrics.blocks_mined.load(Ordering::Relaxed),
            total_rewards_milli: self.metrics.total_rewards_milli.load(Ordering::Relaxed),
            last_block_timestamp: self.metrics.last_block_timestamp.load(Ordering::Relaxed),
            mining_throttle_pct: self.metrics.mining_throttle_pct.load(Ordering::Relaxed),
            chat_messages_mined: self.metrics.chat_messages_mined.load(Ordering::Relaxed),
        }
    }

    /// Hintergrund-Task: Peer-Heartbeat alle N Sekunden
    pub fn start_heartbeat(state: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let peers = state.get_peers();
                let chain_summary = state.chain_summary();

                state.events.publish(NodeEvent::MetricsUpdate {
                    blocks: chain_summary.block_height,
                    documents: chain_summary.total_documents,
                    peers_healthy: peers.iter().filter(|p| p.is_healthy()).count() as u64,
                    peers_total: peers.len() as u64,
                });
            }
        });
    }

    // ─── Block-Mining (Interval-Mining) ───────────────────────────────────────

    /// Berechnet den Block-Reward für einen gegebenen Block-Index.
    ///
    /// Schema: `INITIAL_BLOCK_REWARD / 2^(block_index / HALVING_INTERVAL)`
    /// Gibt `Decimal::ZERO` zurück wenn Reward < MIN oder Reward-Pool leer.
    ///
    /// `pool_balance` = Balance von pool:storage_rewards (woraus Rewards kommen).
    pub fn calculate_block_reward(block_index: u64, pool_balance: Decimal) -> Decimal {
        let min_reward: Decimal = MIN_BLOCK_REWARD.parse().unwrap_or_else(|_| Decimal::new(1, 8));

        // Reward-Pool leer?
        if pool_balance <= Decimal::ZERO {
            return Decimal::ZERO;
        }

        let mut reward: Decimal = INITIAL_BLOCK_REWARD.parse()
            .unwrap_or_else(|_| Decimal::new(10, 0));

        // Halving: Reward halbiert sich alle HALVING_INTERVAL Blöcke
        let halvings = block_index / HALVING_INTERVAL;
        for _ in 0..halvings.min(64) {
            reward /= Decimal::new(2, 0);
            if reward < min_reward {
                return Decimal::ZERO;
            }
        }

        // Nicht mehr als der Pool-Rest
        if reward > pool_balance {
            reward = pool_balance;
        }

        reward.round_dp(8)
    }

    /// Erstellt eine System-Reward-TX für den Block-Validator.
    fn create_reward_tx(validator_wallet: &str, amount: Decimal, block_index: u64) -> TokenTx {
        let chain_id = std::env::var("STONE_NETWORK")
            .map(|n| {
                if n == "mainnet" || n == "main" {
                    "stone-mainnet".to_string()
                } else {
                    "stone-testnet".to_string()
                }
            })
            .unwrap_or_else(|_| "stone-testnet".to_string());

        let mut tx = TokenTx {
            tx_id: String::new(),
            tx_type: TxType::Reward,
            from: "pool:storage_rewards".to_string(),
            to: validator_wallet.to_string(),
            amount,
            fee: Decimal::ZERO,
            nonce: 0,
            timestamp: Utc::now().timestamp(),
            signature: String::new(), // System-TXs brauchen keine Signatur
            memo: format!("Block #{block_index} Mining Reward"),
            chain_id,
            fee_tier: crate::token::FeeTier::Express, // System-TXs immer Express
        };
        tx.tx_id = compute_tx_id(&tx);
        tx
    }

    /// Sammelt pending ChallengeResponses und validiert sie gegen offene Challenges in der Chain.
    ///
    /// Gibt gültige Responses zurück, OHNE sie aus dem Pending-Buffer zu entfernen.
    /// Erst nach erfolgreichem Block-Commit sollen sie via `clear_committed_responses()` entfernt werden.
    fn collect_pending_challenge_responses(
        &self,
        chain: &StoneChain,
    ) -> Vec<crate::storage_proof::ChallengeResponse> {
        let pending = self.pending_challenge_responses.lock().unwrap();
        if pending.is_empty() {
            return Vec::new();
        }

        let current_block = chain.blocks.len() as u64;

        // Sammle alle offenen Challenges aus den letzten DEADLINE Blöcken
        let lookback = crate::storage_proof::CHALLENGE_DEADLINE_BLOCKS as usize + 5;
        let start = chain.blocks.len().saturating_sub(lookback);
        let open_challenges: Vec<&crate::storage_proof::NetworkChallenge> = chain.blocks[start..]
            .iter()
            .flat_map(|b| b.storage_challenges.iter())
            .filter(|c| c.deadline_block >= current_block)
            .collect();

        // Sammle alle schon beantworteten Challenge-IDs
        let answered: std::collections::HashSet<&str> = chain.blocks[start..]
            .iter()
            .flat_map(|b| b.challenge_responses.iter())
            .map(|r| r.challenge_id.as_str())
            .collect();

        // Nur Responses für offene, noch nicht beantwortete Challenges aufnehmen
        let store = crate::storage::ChunkStore::new().ok();

        let valid_responses: Vec<crate::storage_proof::ChallengeResponse> = pending
            .iter()
            .filter(|resp| {
                // Challenge existiert und ist offen?
                let challenge = open_challenges.iter().find(|c| c.challenge_id == resp.challenge_id);
                match challenge {
                    None => {
                        println!("[storage-challenge] ⚠ Response für unbekannte Challenge {} ignoriert", &resp.challenge_id[..12.min(resp.challenge_id.len())]);
                        false
                    }
                    Some(challenge) => {
                        if answered.contains(resp.challenge_id.as_str()) {
                            println!("[storage-challenge] ⚠ Challenge {} schon beantwortet", &resp.challenge_id[..12.min(resp.challenge_id.len())]);
                            return false;
                        }
                        match crate::storage_proof::verify_challenge_response(
                            challenge,
                            resp,
                            store.as_ref(),
                            current_block,
                        ) {
                            Ok(()) => true,
                            Err(e) => {
                                println!("[storage-challenge] ❌ Invalid response: {e}");
                                false
                            }
                        }
                    }
                }
            })
            .cloned()
            .collect();

        valid_responses
    }

    /// Entfernt bereits committete Challenge-Responses aus dem Pending-Buffer.
    /// Wird nach erfolgreichem Block-Commit aufgerufen.
    fn clear_committed_responses(&self, committed_ids: &[String]) {
        if committed_ids.is_empty() {
            return;
        }
        let id_set: std::collections::HashSet<&str> = committed_ids.iter().map(|s| s.as_str()).collect();
        let mut pending = self.pending_challenge_responses.lock().unwrap();
        pending.retain(|r| !id_set.contains(r.challenge_id.as_str()));
    }

    /// Erstellt einen neuen Block (auch ohne Dokumente) mit Mempool-TXs und Block-Reward.
    ///
    /// Wird vom Mining-Loop alle `MINING_INTERVAL_SECS` Sekunden aufgerufen.
    /// Prüft PoA-Berechtigung und erstellt den Block nur wenn diese Node
    /// der ausgewählte Validator ist.
    ///
    /// Single-Node-Modus: Block wird direkt committed.
    /// Multi-Node-Modus: Verwende `prepare_mining_block()` + `commit_mining_block()`.
    pub fn mint_block(&self) -> Result<Block, String> {
        let block = self.prepare_mining_block()?;
        match self.commit_mining_block(block.clone()) {
            Ok(()) => Ok(block),
            Err(e) => {
                // CRITICAL: TXs wurden aus dem Mempool entnommen aber der Block konnte
                // nicht committed werden. TXs zurück in den Mempool legen!
                let mut restored = 0u32;
                for tx in &block.transactions {
                    // Nur echte User-TXs zurücklegen (keine System-TXs wie Reward/Memorial)
                    if tx.tx_type != TxType::Reward && tx.tx_type != TxType::Mint
                        && tx.tx_type != crate::token::transaction::TxType::Memorial
                    {
                        if let Ok(()) = self.mempool.add_tx(tx.clone(), None) {
                            restored += 1;
                        }
                    }
                }
                if restored > 0 {
                    eprintln!(
                        "[mining] ⚠️ Block-Commit fehlgeschlagen, {} TXs zurück in Mempool: {e}",
                        restored
                    );
                }
                // Chat-Batches zurückrollen (Nachrichten wieder auf Pending setzen)
                for batch in &block.chat_batches {
                    self.message_pool.unbatch(&batch.merkle_root);
                }
                Err(e)
            }
        }
    }

    // ─── Competitive PoW: Block-Template für externe Miner ─────────────────

    /// Erstellt ein Block-Template für externe Miner (ohne PoW).
    ///
    /// Der Block wird vollständig vorbereitet (TXs, Reward, Signatur) aber
    /// das Argon2id-PoW-Puzzle wird NICHT gelöst. Das Template enthält alle
    /// Daten die ein externer Miner braucht um den PoW zu lösen.
    ///
    /// Das Template wird in `current_mining_template` gespeichert und kann
    /// per `GET /api/v1/mining/template` abgerufen werden.
    pub fn prepare_block_template(&self) -> Result<MiningTemplate, String> {
        // Validator-Schlüssel laden
        let signing_key = load_or_create_validator_key();
        let validator_wallet = local_validator_pubkey_hex(&signing_key);

        // Reward-Wallet bestimmen
        let reward_wallet = {
            let mw = self.mining_wallet.read().unwrap();
            mw.clone().unwrap_or_else(|| validator_wallet.clone())
        };

        // ── Block-Reward berechnen ──────────────────────────────────────
        let (reward_amount, next_index, _prev_hash) = {
            let chain = self.chain.lock().unwrap();
            let next_idx = chain.blocks.len() as u64;
            let prev = chain.blocks.last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".into());
            let ledger = self.token_ledger.read().unwrap();
            let pool_balance = ledger.balance("pool:storage_rewards");
            (Self::calculate_block_reward(next_idx, pool_balance), next_idx, prev)
        };

        // ── Mempool-TXs + Reward-TX sammeln ────────────────────────────
        let mut pending_txs = self.mempool.drain_all_for_block();
        let user_tx_count = pending_txs.len(); // vor reward

        if reward_amount > Decimal::ZERO {
            let reward_tx = Self::create_reward_tx(&reward_wallet, reward_amount, next_index);
            pending_txs.push(reward_tx);
        }

        // ── Pre-Block-Validierung: Ungültige TXs herausfiltern ──────────
        // Verhindert dass TXs mit unzureichender Balance oder falscher Nonce
        // in den Block aufgenommen werden (Double-Spend-Schutz).
        let pending_txs = {
            let ledger = self.token_ledger.read().unwrap();
            let valid = ledger.filter_valid_txs(&pending_txs);

            // Abgelehnte User-TXs mit zukünftiger Nonce zurück in den Mempool legen.
            // Diese TXs könnten gültig werden wenn vorherige TXs eintreffen.
            let valid_ids: std::collections::HashSet<&str> =
                valid.iter().map(|tx| tx.tx_id.as_str()).collect();
            let mut requeued = 0usize;
            let mut discarded = 0usize;
            for tx in &pending_txs {
                if valid_ids.contains(tx.tx_id.as_str()) {
                    continue;
                }
                // System-TXs nicht requeuen
                if matches!(tx.tx_type, TxType::Reward | TxType::Mint | TxType::Memorial) {
                    continue;
                }
                // Bereits verarbeitete TXs (Duplikate) endgültig verwerfen
                if ledger.is_processed_tx(&tx.tx_id) {
                    discarded += 1;
                    self.mempool.mark_known(&tx.tx_id);
                    continue;
                }
                // Nonce >= erwartet → TX könnte zukünftig gültig werden → zurücklegen
                let expected_nonce = ledger.nonce(&tx.from);
                if tx.nonce >= expected_nonce {
                    if self.mempool.requeue_tx(tx.clone()) {
                        requeued += 1;
                    } else {
                        discarded += 1;
                        println!(
                            "[mining] 🗑️  TX {} endgültig verworfen: Requeue-Limit erreicht (Nonce {} erwartet {})",
                            &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce,
                        );
                    }
                } else {
                    discarded += 1;
                    // Endgültig ungültige TX als "known" markieren damit
                    // Mempool-Sync sie nicht erneut vom Peer holt.
                    self.mempool.mark_known(&tx.tx_id);
                    println!(
                        "[mining] 🗑️  TX {} verworfen: Nonce {} < erwartet {} ({:?})",
                        &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce, tx.tx_type,
                    );
                }
            }
            if requeued > 0 || discarded > 0 {
                println!(
                    "[mining] 📊 Block-Filter: {} User-TXs gedrained, {} valid, {} requeued, {} verworfen",
                    user_tx_count, valid.len().saturating_sub(1), requeued, discarded,
                );
            }

            valid
        };

        // ── Chat-Nachrichten batchen ────────────────────────────────────
        let chat_batches = if self.message_pool.batch_ready() {
            let drained = self.message_pool.drain_for_batch();
            if !drained.is_empty() {
                let msg_ids: Vec<String> = drained.iter().map(|m| m.msg_id.clone()).collect();
                match crate::merkle_batch::build_batch(&drained) {
                    Some((anchor, _tree)) => {
                        self.message_pool.mark_batched(&msg_ids, &anchor.merkle_root);
                        vec![anchor]
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // ── Block vorbereiten (ohne PoW) ────────────────────────────────
        let signer = self.node_id.clone();
        let chain = self.chain.lock().unwrap();
        let mut block = chain.prepare_block(
            Vec::new(),
            Vec::new(),
            pending_txs,
            "system".to_string(),
            signer,
            &self.cluster_key,
            self.role.clone(),
            chat_batches,
        );
        drop(chain);

        // ── Block-Signierung ────────────────────────────────────────────
        let sig = sign_block(&signing_key, &block.hash);
        block.validator_pub_key = validator_wallet.clone();
        block.validator_signature = sig;

        // ── Storage Challenges ──────────────────────────────────────────
        {
            let chain = self.chain.lock().unwrap();
            let chunk_refs = crate::storage_proof::collect_chunk_refs(&chain);
            if !chunk_refs.is_empty() {
                let vs = self.validator_set.read().unwrap();
                let mut known_wallets: Vec<String> = vs.validators.iter()
                    .filter(|v| v.active)
                    .filter_map(|v| if v.public_key_hex.is_empty() { None } else { Some(v.public_key_hex.clone()) })
                    .collect();
                {
                    let trust = self.trust_registry.read().unwrap();
                    for entry in trust.iter() {
                        if !entry.public_key_hex.is_empty() && !known_wallets.contains(&entry.public_key_hex) {
                            known_wallets.push(entry.public_key_hex.clone());
                        }
                    }
                }
                let challenges = crate::storage_proof::generate_network_challenges(
                    &block.previous_hash, block.index, &chunk_refs, &known_wallets, &validator_wallet,
                );
                block.storage_challenges = challenges;

                // Challenge-Responses aufnehmen
                let responses = self.collect_pending_challenge_responses(&chain);
                if !responses.is_empty() {
                    let challenge_reward: Decimal = crate::storage_proof::CHALLENGE_REWARD
                        .parse().unwrap_or(Decimal::new(5, 1));
                    let pool_balance = {
                        let ledger = self.token_ledger.read().unwrap();
                        ledger.balance("pool:storage_rewards")
                    };
                    let mut total = Decimal::ZERO;
                    for resp in &responses {
                        if total + challenge_reward > pool_balance { break; }
                        let chain_id = std::env::var("STONE_NETWORK")
                            .map(|n| if n == "mainnet" || n == "main" { "stone-mainnet".to_string() } else { "stone-testnet".to_string() })
                            .unwrap_or_else(|_| "stone-testnet".to_string());
                        let mut reward_tx = TokenTx {
                            tx_id: String::new(), tx_type: TxType::Reward,
                            from: "pool:storage_rewards".to_string(), to: resp.responder_wallet.clone(),
                            amount: challenge_reward, fee: Decimal::ZERO, nonce: 0,
                            timestamp: Utc::now().timestamp(), signature: String::new(),
                            memo: format!("Storage Challenge Reward ({})", &resp.challenge_id[..12.min(resp.challenge_id.len())]),
                            chain_id, fee_tier: crate::token::FeeTier::Express,
                        };
                        reward_tx.tx_id = compute_tx_id(&reward_tx);
                        block.transactions.push(reward_tx);
                        total += challenge_reward;
                    }
                    if total > Decimal::ZERO {
                        block.merkle_root = crate::blockchain::compute_merkle_root(
                            &block.documents, &block.tombstones, &block.transactions,
                        );
                    }
                    block.challenge_responses = responses;
                }

                // Block-Hash neu berechnen
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                block.validator_signature = sign_block(&signing_key, &block.hash);
            }
        }

        // ── PoW-Difficulty bestimmen ────────────────────────────────────
        let difficulty = {
            let chain = self.chain.lock().unwrap();
            crate::consensus::get_current_pow_difficulty(&chain.blocks, block.index)
        };
        block.pow_difficulty = difficulty;

        // ── PoS/PoW Hybrid: Effektive Difficulty berechnen ───────────────
        let eff_difficulty = {
            let pool = self.staking_pool.read().unwrap();
            let miner_stake = pool.stakers.get(&validator_wallet)
                .map(|e| e.staked_amount)
                .unwrap_or(rust_decimal::Decimal::ZERO);
            let total_staked = pool.total_staked;
            crate::consensus::effective_pow_difficulty(difficulty, miner_stake, total_staked)
        };
        block.effective_difficulty = eff_difficulty;

        // ── Kumulative Difficulty setzen ─────────────────────────────────
        {
            let chain = self.chain.lock().unwrap();
            let parent_cd = chain.blocks.last()
                .map(|b| b.cumulative_difficulty)
                .unwrap_or(0);
            block.cumulative_difficulty = parent_cd
                + crate::blockchain::block_work_effective(eff_difficulty, difficulty);
        }

        // Template-ID: Hash aus Block-Index + Timestamp + prev_hash
        let template_id = {
            use sha2::{Sha256, Digest};
            let mut h = Sha256::new();
            h.update(block.index.to_le_bytes());
            h.update(block.timestamp.to_le_bytes());
            h.update(block.previous_hash.as_bytes());
            hex::encode(h.finalize())[..16].to_string()
        };

        let template = MiningTemplate {
            block_index: block.index,
            previous_hash: block.previous_hash.clone(),
            difficulty,
            effective_difficulty: eff_difficulty,
            timestamp: block.timestamp,
            validator_pubkey: validator_wallet.clone(),
            block_hash_pre_pow: block.hash.clone(),
            tx_count: block.transactions.len(),
            reward: reward_amount.to_string(),
            template_id: template_id.clone(),
        };

        println!(
            "[mining] 📋 Template #{} erstellt: Block #{}, {} TXs, d={}/{}, Reward: {} STONE",
            &template_id[..8], block.index, block.transactions.len(),
            eff_difficulty, difficulty, reward_amount,
        );

        // Template + Block speichern
        {
            let mut tmpl = self.current_mining_template.write().unwrap();
            *tmpl = Some((template.clone(), block));
        }

        Ok(template)
    }

    /// Nimmt eine PoW-Lösung eines externen Miners entgegen und committed den Block.
    ///
    /// 1. Prüft ob das Template noch aktuell ist
    /// 2. Verifiziert den Argon2id-PoW
    /// 3. Setzt PoW-Felder im Block
    /// 4. Committed den Block + Broadcast
    pub fn submit_mining_solution(
        &self,
        submission: &MiningSubmission,
    ) -> Result<Block, String> {
        // Template laden und prüfen
        let (template, mut block) = {
            let tmpl = self.current_mining_template.read().unwrap();
            match tmpl.as_ref() {
                Some((t, b)) => {
                    if t.template_id != submission.template_id {
                        return Err("Template-ID stimmt nicht überein (veraltet?)".into());
                    }
                    (t.clone(), b.clone())
                }
                None => return Err("Kein aktives Mining-Template vorhanden".into()),
            }
        };

        // Chain-Konsistenz: Ist der Block noch der nächste?
        {
            let chain = self.chain.lock().unwrap();
            let expected = chain.blocks.len() as u64;
            if block.index != expected {
                // Template ist veraltet (zwischenzeitlich neuer Block empfangen)
                // TXs zurück in Mempool
                self.restore_block_txs(&block);
                // Template invalidieren
                *self.current_mining_template.write().unwrap() = None;
                return Err(format!(
                    "Block #{} veraltet (Chain ist bei #{})", block.index, expected
                ));
            }
        }

        // PoW verifizieren (gegen effective_difficulty = Stake-reduziertes Target)
        let verify_difficulty = if template.effective_difficulty > 0 {
            template.effective_difficulty
        } else {
            template.difficulty
        };
        if verify_difficulty > 0 {
            let valid = crate::consensus::verify_argon2_pow(
                &block.previous_hash,
                block.index,
                &template.validator_pubkey,
                submission.nonce,
                &submission.pow_hash,
                verify_difficulty,
            );
            if !valid {
                return Err("Ungültiger Argon2id-PoW (Hash oder Difficulty falsch)".into());
            }
        }

        // PoW-Felder setzen
        block.pow_nonce = submission.nonce;
        block.pow_hash = submission.pow_hash.clone();
        block.pow_difficulty = template.difficulty;
        block.effective_difficulty = template.effective_difficulty;

        // Hash + Signaturen neu berechnen (PoW-Felder fließen in Block-Hash ein)
        block.hash = crate::blockchain::calculate_hash(&block);
        block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
        let signing_key = load_or_create_validator_key();
        block.validator_signature = sign_block(&signing_key, &block.hash);

        // Template invalidieren (wurde gelöst)
        *self.current_mining_template.write().unwrap() = None;

        // Block committen
        self.commit_mining_block(block.clone())?;

        println!(
            "[mining] ✅ Externer PoW akzeptiert: Block #{}, nonce={}, d={}/{}",
            block.index, submission.nonce, template.effective_difficulty, template.difficulty,
        );

        Ok(block)
    }

    /// Stellt TXs eines gescheiterten Blocks zurück in den Mempool.
    fn restore_block_txs(&self, block: &Block) {
        for tx in &block.transactions {
            if tx.tx_type != TxType::Reward && tx.tx_type != TxType::Mint
                && tx.tx_type != crate::token::transaction::TxType::Memorial
            {
                let _ = self.mempool.add_tx(tx.clone(), None);
            }
        }
        for batch in &block.chat_batches {
            self.message_pool.unbatch(&batch.merkle_root);
        }
    }

    // ─── Mining-Wallet Persistierung ───────────────────────────────────────

    fn mining_config_path() -> String {
        let dir = std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| "stone_data".to_string());
        format!("{dir}/mining_config.json")
    }

    fn load_mining_wallet() -> Option<String> {
        let path = Self::mining_config_path();
        let data = std::fs::read_to_string(&path).ok()?;
        let config: serde_json::Value = serde_json::from_str(&data).ok()?;
        config.get("mining_wallet")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    pub fn save_mining_wallet(wallet: &Option<String>) {
        let path = Self::mining_config_path();
        let config = serde_json::json!({
            "mining_wallet": wallet.as_deref().unwrap_or(""),
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        if let Ok(json) = serde_json::to_string_pretty(&config) {
            if let Err(e) = std::fs::write(&path, json) {
                eprintln!("[mining] ⚠ Konnte mining_config.json nicht speichern: {e}");
            }
        }
    }

    /// Gibt die aktive Reward-Wallet zurück: mining_wallet falls gesetzt, sonst validator_wallet.
    pub fn effective_reward_wallet(&self) -> String {
        let mw = self.mining_wallet.read().unwrap();
        if let Some(ref wallet) = *mw {
            wallet.clone()
        } else {
            let signing_key = load_or_create_validator_key();
            local_validator_pubkey_hex(&signing_key)
        }
    }

    /// Erstellt einen neuen Mining-Block **ohne** ihn zu committen.
    ///
    /// Der Block ist vollständig (Hash, Validator-Signatur) und kann
    /// an Peers zur Abstimmung gesendet werden.
    /// Erst `commit_mining_block()` wendet ihn auf Chain, Ledger und StakingPool an.
    pub fn prepare_mining_block(&self) -> Result<Block, String> {
        // ── Validator-Schlüssel laden (Wallet = Ed25519 Public Key Hex) ───
        let signing_key = load_or_create_validator_key();
        let validator_wallet = local_validator_pubkey_hex(&signing_key);

        // ── Reward-Wallet bestimmen: gebundene Mining-Wallet oder Validator-Wallet
        let reward_wallet = {
            let mw = self.mining_wallet.read().unwrap();
            mw.clone().unwrap_or_else(|| validator_wallet.clone())
        };

        // ── PoA-Check: Round-Robin Validator-Rotation + Lite-PoW Fallback ──
        // Lock-Ordnung: chain zuerst (Daten cachen) → drop → dann validator_set
        let (chain_next_index, _chain_prev_hash) = {
            let chain = self.chain.lock().unwrap();
            let idx = chain.blocks.len() as u64;
            let hash = chain.blocks.last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".into());
            (idx, hash)
        };
        // Phase 1: Round-Robin — Jeder aktive Validator kommt der Reihe nach dran.
        // Phase 2: Lite-PoW Fallback — wenn der Primäre ausfällt, darf jeder
        //          aktive Validator mit einem gelösten PoW-Puzzle einspringen.
        let mut is_pow_fallback = false;
        {
            let vs = self.validator_set.read().unwrap();
            if !vs.validators.is_empty() {
                if !vs.is_active_validator(&self.node_id) {
                    return Err("Mining: Node ist kein aktiver Validator".into());
                }

                // Mindest-Validator-Anzahl prüfen
                let active = vs.active_count();
                if active < 2 {
                    // Einzelner Validator: Round-Robin/PoA deaktiviert, direkt minen
                    println!(
                        "[mining] ⚠️ Nur {} aktiver Validator — PoA-Rotation deaktiviert",
                        active
                    );
                } else {
                    if active < 3 {
                        println!(
                            "[mining] ⚠️ Nur {} aktive Validatoren — BFT-Sicherheit eingeschränkt (min. 3 empfohlen)",
                            active
                        );
                    }

                let (stakes, jailed, wallet_map) = self.build_selection_context();

                // Beide Algorithmen prüfen: gewichtete Auswahl (= Peer-Validierung)
                // UND Round-Robin (= lokale Rotation). Primary wenn einer zutrifft.
                let is_weighted_turn = vs.is_selected_validator_weighted(
                    &self.node_id, &_chain_prev_hash, chain_next_index,
                    &stakes, &jailed, &wallet_map,
                );
                let is_rr_turn = vs.is_round_robin_turn(&self.node_id, chain_next_index, &jailed);
                let is_primary = is_weighted_turn || is_rr_turn;

                if !is_primary {
                    // Nicht unser Slot.
                    // Prüfe ob der primäre Validator seinen Slot verpasst hat.
                    let last_block_age = {
                        let chain = self.chain.lock().unwrap();
                        chain.blocks.last()
                            .map(|b| (Utc::now().timestamp() - b.timestamp) as u64)
                            .unwrap_or(u64::MAX)
                    };

                    // Fallback erst nach 2× MINING_INTERVAL (gibt dem Primären genug Zeit)
                    let fallback_threshold = MINING_INTERVAL_SECS * 2;
                    if last_block_age < fallback_threshold {
                        let selected = vs.select_validator_round_robin(chain_next_index, &jailed)
                            .map(|v| v.node_id.clone())
                            .unwrap_or_else(|| "?".into());
                        return Err(format!(
                            "Mining: Node '{}' nicht ausgewählt für Block #{chain_next_index} (→ '{selected}')",
                            self.node_id
                        ));
                    }

                    // Primärer Validator hat seinen Slot verpasst → Lite-PoW Fallback
                    println!(
                        "[mining] ⚡ Round-Robin Fallback für Block #{}: Primärer Validator hat {}s nicht produziert – löse Lite-PoW",
                        chain_next_index, last_block_age
                    );
                    is_pow_fallback = true;
                }
                } // end active >= 2
            }
        }

        // ── Block-Reward berechnen ────────────────────────────────────────
        let (reward_amount, next_index) = {
            let chain = self.chain.lock().unwrap();
            let next_idx = chain.blocks.len() as u64;
            let ledger = self.token_ledger.read().unwrap();
            let pool_balance = ledger.balance("pool:storage_rewards");
            (Self::calculate_block_reward(next_idx, pool_balance), next_idx)
        };

        // ── Mempool-TXs + Reward-TX sammeln ──────────────────────────────
        let mut pending_txs = self.mempool.drain_all_for_block();
        let user_tx_count = pending_txs.len(); // vor reward

        // Log ChatMessage TXs für Debugging
        let chat_tx_count = pending_txs.iter()
            .filter(|tx| tx.tx_type == TxType::ChatMessage)
            .count();
        if chat_tx_count > 0 {
            println!(
                "[mining] 💬 {} ChatMessage TX(s) werden in Block #{} aufgenommen",
                chat_tx_count, next_index
            );
        }

        // Reward-TX hinzufügen (falls Reward > 0)
        let has_user_txs = !pending_txs.is_empty();
        if reward_amount > Decimal::ZERO {
            let reward_tx = Self::create_reward_tx(&reward_wallet, reward_amount, next_index);
            pending_txs.push(reward_tx);
        }

        // ── Pre-Block-Validierung: Ungültige TXs herausfiltern ──────────
        let pending_txs = {
            let ledger = self.token_ledger.read().unwrap();
            let valid = ledger.filter_valid_txs(&pending_txs);

            // Abgelehnte User-TXs mit zukünftiger Nonce zurück in den Mempool legen
            let valid_ids: std::collections::HashSet<&str> =
                valid.iter().map(|tx| tx.tx_id.as_str()).collect();
            let mut requeued = 0usize;
            let mut discarded = 0usize;
            for tx in &pending_txs {
                if valid_ids.contains(tx.tx_id.as_str()) {
                    continue;
                }
                if matches!(tx.tx_type, TxType::Reward | TxType::Mint | TxType::Memorial) {
                    continue;
                }
                // Bereits verarbeitete TXs (Duplikate) endgültig verwerfen
                if ledger.is_processed_tx(&tx.tx_id) {
                    discarded += 1;
                    self.mempool.mark_known(&tx.tx_id);
                    continue;
                }
                let expected_nonce = ledger.nonce(&tx.from);
                if tx.nonce >= expected_nonce {
                    if self.mempool.requeue_tx(tx.clone()) {
                        requeued += 1;
                    } else {
                        discarded += 1;
                        println!(
                            "[mining] 🗑️  TX {} endgültig verworfen: Requeue-Limit erreicht (Nonce {} erwartet {})",
                            &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce,
                        );
                    }
                } else {
                    discarded += 1;
                    // Endgültig ungültige TX als "known" markieren damit
                    // Mempool-Sync sie nicht erneut vom Peer holt.
                    self.mempool.mark_known(&tx.tx_id);
                    println!(
                        "[mining] 🗑️  TX {} verworfen: Nonce {} < erwartet {} ({:?})",
                        &tx.tx_id[..12.min(tx.tx_id.len())], tx.nonce, expected_nonce, tx.tx_type,
                    );
                }
            }
            if requeued > 0 || discarded > 0 {
                println!(
                    "[mining] 📊 Block-Filter: {} User-TXs gedrained, {} valid, {} requeued, {} verworfen",
                    user_tx_count, valid.len().saturating_sub(1), requeued, discarded,
                );
            }

            valid
        };

        // Blöcke werden IMMER erzeugt — auch ohne User-TXs.
        // Der Block-Reward, Network-Challenges und Shard-Repair-Rewards
        // sind allein schon Grund genug einen Block zu minen.
        // Leere Blöcke treiben die Chain voran und ermöglichen:
        //  - Regelmäßige Storage-Challenges
        //  - Repair-Reward-Auszahlung
        //  - Konsistente Block-Time für das Netzwerk
        if !has_user_txs {
            println!(
                "[mining] Block #{next_index}: keine User-TXs → Reward-only Block"
            );
        }

        // ── Chat-Nachrichten aus dem MessagePool batchen ──────────────────
        let chat_batches = if self.message_pool.batch_ready() {
            let drained = self.message_pool.drain_for_batch();
            if !drained.is_empty() {
                let msg_ids: Vec<String> = drained.iter().map(|m| m.msg_id.clone()).collect();
                match crate::merkle_batch::build_batch(&drained) {
                    Some((anchor, _tree)) => {
                        println!(
                            "[mining] 📦 Chat-Batch: {} Nachrichten, seq {}-{}, root: {}…",
                            anchor.batch_size,
                            anchor.seq_start,
                            anchor.seq_end,
                            &anchor.merkle_root[..12],
                        );
                        // Nachrichten als "batched" markieren
                        self.message_pool.mark_batched(&msg_ids, &anchor.merkle_root);
                        vec![anchor]
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // ── Block vorbereiten (ohne Commit in die Chain) ──────────────────
        let signer = self.node_id.clone();
        let chain = self.chain.lock().unwrap();
        let mut block = chain.prepare_block(
            Vec::new(),
            Vec::new(),
            pending_txs,
            "system".to_string(),
            signer,
            &self.cluster_key,
            self.role.clone(),
            chat_batches,
        );

        // ── PoA: Block-Signierung ────────────────────────────────────────
        let sig = sign_block(&signing_key, &block.hash);
        block.validator_pub_key = validator_wallet.clone();
        block.validator_signature = sig;

        // ── Network Storage Challenges: Challenge andere Nodes ───────────
        {
            let chunk_refs = crate::storage_proof::collect_chunk_refs(&chain);
            if !chunk_refs.is_empty() {
                // Bekannte Validator-Wallets sammeln
                let vs = self.validator_set.read().unwrap();
                let mut known_wallets: Vec<String> = vs.validators.iter()
                    .filter(|v| v.active)
                    .filter_map(|v| if v.public_key_hex.is_empty() { None } else { Some(v.public_key_hex.clone()) })
                    .collect();
                // Auch Peers' Wallets aus Trust-Registry einbeziehen
                {
                    let trust = self.trust_registry.read().unwrap();
                    for entry in trust.iter() {
                        if !entry.public_key_hex.is_empty() && !known_wallets.contains(&entry.public_key_hex) {
                            known_wallets.push(entry.public_key_hex.clone());
                        }
                    }
                }

                let challenges = crate::storage_proof::generate_network_challenges(
                    &block.previous_hash,
                    block.index,
                    &chunk_refs,
                    &known_wallets,
                    &validator_wallet,
                );

                if !challenges.is_empty() {
                    println!(
                        "[storage-challenge] 📋 Block #{}: {} Network-Challenges erstellt",
                        block.index, challenges.len()
                    );
                    for c in &challenges {
                        println!(
                            "[storage-challenge]   → Node {}… Chunk {}… Offset {} (Deadline: #{})",
                            &c.target_wallet[..12.min(c.target_wallet.len())],
                            &c.chunk_hash[..12.min(c.chunk_hash.len())],
                            c.offset,
                            c.deadline_block
                        );
                    }
                }

                // Challenges hinzufügen und Block-Hash neu berechnen
                block.storage_challenges = challenges;

                // Pending ChallengeResponses aus dem Mempool holen
                // (diese wurden von herausgeforderten Nodes eingereicht)
                let responses = self.collect_pending_challenge_responses(&chain);
                let mut challenge_rewards_total = Decimal::ZERO;
                if !responses.is_empty() {
                    println!(
                        "[storage-challenge] ✅ {} Challenge-Responses in Block #{} aufgenommen",
                        responses.len(), block.index
                    );

                    // Challenge-Reward-TXs: Jede gültige Response bekommt CHALLENGE_REWARD STONE
                    let challenge_reward: Decimal = crate::storage_proof::CHALLENGE_REWARD
                        .parse().unwrap_or(Decimal::new(5, 1)); // 0.5 STONE Fallback
                    let pool_balance = {
                        let ledger = self.token_ledger.read().unwrap();
                        ledger.balance("pool:storage_rewards")
                    };
                    for resp in &responses {
                        if challenge_rewards_total + challenge_reward > pool_balance {
                            println!(
                                "[storage-challenge] ⚠ Reward-Pool reicht nicht für weitere Challenge-Rewards"
                            );
                            break;
                        }
                        let chain_id = std::env::var("STONE_NETWORK")
                            .map(|n| if n == "mainnet" || n == "main" { "stone-mainnet".to_string() } else { "stone-testnet".to_string() })
                            .unwrap_or_else(|_| "stone-testnet".to_string());
                        let mut reward_tx = TokenTx {
                            tx_id: String::new(),
                            tx_type: TxType::Reward,
                            from: "pool:storage_rewards".to_string(),
                            to: resp.responder_wallet.clone(),
                            amount: challenge_reward,
                            fee: Decimal::ZERO,
                            nonce: 0,
                            timestamp: Utc::now().timestamp(),
                            signature: String::new(),
                            memo: format!("Storage Challenge Reward ({})", &resp.challenge_id[..12.min(resp.challenge_id.len())]),
                            chain_id,
                            fee_tier: crate::token::FeeTier::Express,
                        };
                        reward_tx.tx_id = compute_tx_id(&reward_tx);
                        block.transactions.push(reward_tx);
                        challenge_rewards_total += challenge_reward;
                    }
                    if challenge_rewards_total > Decimal::ZERO {
                        // Merkle-Root muss wegen neuer TXs neu berechnet werden
                        block.merkle_root = crate::blockchain::compute_merkle_root(
                            &block.documents, &block.tombstones, &block.transactions,
                        );
                        println!(
                            "[storage-challenge] 💰 {} STONE Challenge-Rewards in Block #{}",
                            challenge_rewards_total, block.index
                        );
                    }
                }
                block.challenge_responses = responses;

                // ── Shard-Repair-Rewards: Miner die degradierte Shards repariert haben ──
                let pending_repairs: Vec<crate::storage_proof::RepairReward> = {
                    let mut repairs = self.pending_repair_rewards.lock().unwrap();
                    std::mem::take(&mut *repairs)
                };
                if !pending_repairs.is_empty() {
                    let repair_reward: Decimal = crate::storage_proof::REPAIR_REWARD
                        .parse().unwrap_or(Decimal::new(25, 2)); // 0.25 STONE Fallback
                    let pool_balance_now = {
                        let ledger = self.token_ledger.read().unwrap();
                        ledger.balance("pool:storage_rewards")
                    };
                    let mut repair_rewards_total = Decimal::ZERO;
                    for repair in &pending_repairs {
                        if repair_rewards_total + repair_reward > pool_balance_now - challenge_rewards_total {
                            println!(
                                "[shard-repair] ⚠ Reward-Pool reicht nicht für weitere Repair-Rewards"
                            );
                            break;
                        }
                        let chain_id = std::env::var("STONE_NETWORK")
                            .map(|n| if n == "mainnet" || n == "main" { "stone-mainnet".to_string() } else { "stone-testnet".to_string() })
                            .unwrap_or_else(|_| "stone-testnet".to_string());
                        let mut reward_tx = TokenTx {
                            tx_id: String::new(),
                            tx_type: TxType::Reward,
                            from: "pool:storage_rewards".to_string(),
                            to: repair.repairer_wallet.clone(),
                            amount: repair_reward,
                            fee: Decimal::ZERO,
                            nonce: 0,
                            timestamp: Utc::now().timestamp(),
                            signature: String::new(),
                            memo: format!(
                                "Shard Repair Reward ({}[{}])",
                                &repair.chunk_hash[..12.min(repair.chunk_hash.len())],
                                repair.shard_index
                            ),
                            chain_id,
                            fee_tier: crate::token::FeeTier::Express,
                        };
                        reward_tx.tx_id = compute_tx_id(&reward_tx);
                        block.transactions.push(reward_tx);
                        repair_rewards_total += repair_reward;
                    }
                    if repair_rewards_total > Decimal::ZERO {
                        block.merkle_root = crate::blockchain::compute_merkle_root(
                            &block.documents, &block.tombstones, &block.transactions,
                        );
                        println!(
                            "[shard-repair] 🔧 {} STONE Repair-Rewards in Block #{} ({} Shards repariert)",
                            repair_rewards_total, block.index, pending_repairs.len()
                        );
                    }
                }

                // Block-Hash neu berechnen (weil storage_challenges den Hash beeinflusst)
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                let new_sig = sign_block(&signing_key, &block.hash);
                block.validator_signature = new_sig;
            }
        }

        // ── Lite-PoW lösen (nur bei Fallback-Mining) ─────────────────────
        if is_pow_fallback {
            use crate::consensus::{solve_lite_pow, BLOCK_POW_DIFFICULTY};
            let pow_nonce = solve_lite_pow(
                &block.previous_hash,
                block.index,
                &self.node_id,
                BLOCK_POW_DIFFICULTY,
            );
            block.pow_nonce = pow_nonce;
            // Hash neu berechnen (pow_nonce fließt in den Hash ein)
            block.hash = crate::blockchain::calculate_hash(&block);
            block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
            block.validator_signature = sign_block(&signing_key, &block.hash);
            println!(
                "[mining] 🔨 Lite-PoW gelöst für Block #{}: nonce={pow_nonce} (difficulty={})",
                block.index, BLOCK_POW_DIFFICULTY
            );
        }

        // ── Argon2id CPU-PoW lösen (ab Activation-Block) ────────────────
        {
            use crate::consensus::{
                get_current_pow_difficulty, solve_argon2_pow,
                ARGON2_POW_ACTIVATION_BLOCK,
            };
            let chain_ref = self.chain.lock().unwrap();
            let difficulty = get_current_pow_difficulty(&chain_ref.blocks, block.index);
            drop(chain_ref);

            if block.index >= ARGON2_POW_ACTIVATION_BLOCK && difficulty > 0 {
                println!(
                    "[mining] ⛏️  Starte Argon2id-PoW für Block #{} (Difficulty: {} Bits, Memory: 64 MiB)…",
                    block.index, difficulty,
                );
                let (nonce, pow_hash) = solve_argon2_pow(
                    &block.previous_hash,
                    block.index,
                    &validator_wallet,
                    difficulty,
                );
                block.pow_nonce = nonce;
                block.pow_hash = pow_hash;
                block.pow_difficulty = difficulty;

                // Hash + Signaturen neu berechnen (pow_hash + pow_difficulty fließen in Block-Hash ein)
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                block.validator_signature = sign_block(&signing_key, &block.hash);
            }
        }

        println!(
            "[mining] ⛏️  Block #{} vorbereitet – {} TXs, Reward: {} STONE → {}{}{}",
            block.index,
            block.transactions.len(),
            reward_amount,
            &reward_wallet[..16.min(reward_wallet.len())],
            if is_pow_fallback { " [PoW-Fallback]" } else { "" },
            if !block.pow_hash.is_empty() { format!(" [Argon2id: d={}]", block.pow_difficulty) } else { String::new() },
        );

        Ok(block)
    }

    /// Committed einen vorbereiteten Block: Chain, Ledger, StakingPool, Metriken, Events.
    ///
    /// Wird nach erfolgreicher Voting-Phase (Multi-Node) oder direkt (Single-Node) aufgerufen.
    pub fn commit_mining_block(&self, block: Block) -> Result<(), String> {
        let signing_key = load_or_create_validator_key();
        let validator_wallet = local_validator_pubkey_hex(&signing_key);

        // ── Block in die Chain einfügen ───────────────────────────────────
        {
            let mut chain = self.chain.lock().unwrap();
            // Prüfe dass Block zum nächsten Index passt
            let expected_idx = chain.blocks.len() as u64;
            if block.index != expected_idx {
                return Err(format!(
                    "Block-Index {} passt nicht (erwartet: {})", block.index, expected_idx
                ));
            }
            chain.commit_block(block.clone());
        }

        // ── Token-TXs im Ledger verarbeiten ──────────────────────────────
        if !block.transactions.is_empty() {
            let mut ledger = self.token_ledger.write().unwrap();
            // Fee-Split: Validator-Wallet setzen BEVOR TXs verarbeitet werden
            ledger.set_current_validator(Some(validator_wallet.clone()));
            // TXs wurden bereits durch filter_valid_txs() validiert →
            // Trotzdem Balance/Nonce prüfen (kein replay_mode), damit
            // auch per Gossip empfangene Blöcke korrekt geprüft werden.
            let receipts = ledger.apply_block_txs(&block.transactions, block.index);
            ledger.set_current_validator(None);

            // ── Staking-TXs im StakingPool verarbeiten ────────────────────
            self.apply_staking_from_txs(&block.transactions);

            if !receipts.is_empty() {
                if let Err(e) = ledger.persist() {
                    eprintln!("[mining] Ledger-Persistierung nach Block #{} fehlgeschlagen: {e}", block.index);
                }
            }
            // Sync-Marker aktualisieren (auch wenn keine Receipts — Block ist in der Chain)
            ledger.set_last_synced_block(block.index);
        }

        // Block wurde bereits durch commit_block() → persist_last_block() persistiert.

        // ── Chat-Batch-Messages als confirmed markieren ───────────────────
        for batch in &block.chat_batches {
            let msg_ids = self.message_pool.msg_ids_for_batch(&batch.merkle_root);
            if !msg_ids.is_empty() {
                // Batch-Record für Proof-Generierung speichern
                let msgs = self.message_pool.messages_in_seq_range(batch.seq_start, batch.seq_end);
                self.message_pool.store_batch_record(&batch.merkle_root, &msgs, block.index);

                self.message_pool.mark_confirmed(&msg_ids, block.index);
                println!(
                    "[mining] ✅ Chat-Batch bestätigt: {} Nachrichten in Block #{}",
                    msg_ids.len(), block.index,
                );
            }
        }

        // ── Validator-Statistik aktualisieren ─────────────────────────────
        {
            let mut vs_w = self.validator_set.write().unwrap();
            if let Some(v) = vs_w.get_mut(&self.node_id) {
                v.blocks_signed += 1;
                vs_w.save();
            }
        }

        // ── Events ───────────────────────────────────────────────────────
        self.events.publish(NodeEvent::BlockAdded {
            index: block.index,
            hash: block.hash.clone(),
            docs: 0,
            owner: "system".into(),
            timestamp: block.timestamp,
        });

        for tx in &block.transactions {
            self.events.publish(NodeEvent::TokenTransfer {
                tx_id: tx.tx_id.clone(),
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount: tx.amount.to_string(),
                tx_type: tx.tx_type.to_string(),
                block_index: block.index,
            });
        }

        // ── Mining-Metriken aktualisieren ─────────────────────────────────
        self.metrics.blocks_mined.fetch_add(1, Ordering::Relaxed);
        self.metrics.last_block_timestamp.store(block.timestamp as u64, Ordering::Relaxed);

        use rust_decimal::prelude::ToPrimitive;
        // Reward aus der Reward-TX extrahieren
        let reward_amount = block.transactions.iter()
            .find(|tx| tx.tx_type == TxType::Reward)
            .map(|tx| tx.amount)
            .unwrap_or(Decimal::ZERO);
        let reward_milli = (reward_amount * Decimal::new(1000, 0))
            .to_u64()
            .unwrap_or(0);
        self.metrics.total_rewards_milli.fetch_add(reward_milli, Ordering::Relaxed);

        let chat_count = block.transactions.iter()
            .filter(|tx| tx.tx_type == TxType::ChatMessage)
            .count() as u64;
        if chat_count > 0 {
            self.metrics.chat_messages_mined.fetch_add(chat_count, Ordering::Relaxed);
        }

        println!(
            "[mining] ✅ Block #{} committed – {} TXs, Validator: {}",
            block.index,
            block.transactions.len(),
            &validator_wallet[..16.min(validator_wallet.len())],
        );

        // ── Auto-Snapshot (alle SNAPSHOT_INTERVAL Blöcke, NUR Bootstrap-Nodes) ──
        if crate::snapshot::should_create_snapshot(block.index)
            && crate::network::is_bootstrap_node()
        {
            let genesis_hash = {
                let chain = self.chain.lock().unwrap();
                chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default()
            };
            let latest_hash = block.hash.clone();
            let height = block.index;
            std::thread::spawn(move || {
                match crate::snapshot::create_snapshot(height, &genesis_hash, &latest_hash) {
                    Ok((_path, meta)) => {
                        eprintln!(
                            "[snapshot] 📸 Auto-Snapshot bei Block #{}: {:.1} MB",
                            meta.block_height,
                            meta.archive_size as f64 / 1_048_576.0
                        );
                    }
                    Err(e) => eprintln!("[snapshot] ⚠️  Auto-Snapshot fehlgeschlagen: {e}"),
                }
            });
        }

        Ok(())
    }

    /// Hintergrund-Task: Continuous Mining-Loop (Competitive PoW).
    ///
    /// Statt timer-basiertem Intervall-Mining (PoA) wird jetzt:
    /// 1. Kontinuierlich ein Block-Template bereitgehalten
    /// 2. Externe Miner lösen das Argon2id-PoW per API (`/mining/template` + `/mining/submit`)
    /// 3. Gossip-Blöcke von anderen Nodes invalidieren das lokale Template
    /// 4. Template wird alle TEMPLATE_REFRESH_SECS Sekunden aktualisiert
    pub fn start_mining_loop(state: Arc<Self>) {
        println!(
            "[mining] ⛏️  Competitive-PoW Mining-Loop gestartet (Target: {}s, Reward: {} STONE, Halving: alle {} Blöcke)",
            TARGET_BLOCK_TIME_SECS, INITIAL_BLOCK_REWARD, HALVING_INTERVAL
        );

        tokio::spawn(async move {
            // Erste Wartezeit: 15s (P2P-Netzwerk aufbauen lassen)
            tokio::time::sleep(Duration::from_secs(15)).await;

            let template_interval = Duration::from_secs(TEMPLATE_REFRESH_SECS);
            let mut ticker = tokio::time::interval(template_interval);
            let mut last_template_height: u64 = 0;

            loop {
                ticker.tick().await;

                // ── Initial-Sync abwarten ─────────────────────────────────
                if !state.metrics.initial_sync_done.load(Ordering::Relaxed) {
                    let uptime = Utc::now().timestamp() - state.started_at;
                    let sync_timeout = 60_i64; // 60s Sync-Timeout für schnellere Block-Time
                    if uptime < sync_timeout {
                        continue;
                    }
                    println!("[mining] ⏰ Initial-Sync Timeout ({}s) – starte Mining", sync_timeout);
                    state.metrics.initial_sync_done.store(true, Ordering::Relaxed);

                    // Token-Ledger aus synced Chain rebuilden
                    {
                        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                        if chain.blocks.len() > 1 {
                            let rebuilt = crate::token::TokenLedger::rebuild_from_chain(&chain.blocks);
                            let mut ledger = state.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                            *ledger = rebuilt;
                            println!(
                                "[token] 🔄 Ledger nach Initial-Sync rebuilt: {} Accounts, Supply: {}",
                                ledger.account_count(),
                                ledger.total_supply()
                            );
                        }
                    }
                }

                // Mining-Throttle prüfen
                {
                    let throttle = state.metrics.mining_throttle_pct.load(Ordering::Relaxed);
                    if throttle == 0 {
                        continue; // Mining komplett deaktiviert
                    }
                }

                // Nicht minen wenn Peers weiter sind
                {
                    let our_height = state.chain.lock().unwrap().blocks.len() as u64;
                    let max_peer_height = {
                        let peers = state.peers.read().unwrap();
                        peers.iter()
                            .filter(|p| p.is_healthy())
                            .map(|p| p.block_height)
                            .max()
                            .unwrap_or(0)
                    };
                    if max_peer_height > our_height + 1 {
                        // Template invalidieren wenn wir hinterher sind
                        *state.current_mining_template.write().unwrap() = None;
                        continue;
                    }
                }

                // Mempool: abgelaufene TXs bereinigen (alle 30s)
                let current_height = state.chain.lock().unwrap().blocks.len() as u64;
                if current_height != last_template_height {
                    let evicted = state.mempool.evict_expired();
                    if evicted > 0 {
                        println!("[mining] 🧹 {} abgelaufene TXs aus Mempool entfernt", evicted);
                    }
                }

                // ── Stall-Warnung ────────────────────────────────────────
                {
                    let pending = state.mempool.pending_count();
                    if pending > 0 {
                        let chain = state.chain.lock().unwrap();
                        if let Some(last) = chain.blocks.last() {
                            let age = Utc::now().timestamp() - last.timestamp;
                            if age > (TARGET_BLOCK_TIME_SECS as i64 * 5) {
                                println!(
                                    "[mining] ⚠ Stall: {} pending TXs, letzter Block vor {}s (kein Miner aktiv?)",
                                    pending, age,
                                );
                            }
                        }
                    }
                }

                // ── Template aktualisieren ────────────────────────────────
                // Nur neues Template erstellen wenn:
                // 1. Noch kein Template vorhanden, oder
                // 2. Neuer Block seit letztem Template (Height hat sich geändert)
                let needs_new_template = {
                    let tmpl = state.current_mining_template.read().unwrap();
                    match tmpl.as_ref() {
                        Some((t, _)) => t.block_index != current_height,
                        None => true,
                    }
                };

                if needs_new_template {
                    match state.prepare_block_template() {
                        Ok(template) => {
                            last_template_height = template.block_index;
                        }
                        Err(e) => {
                            if !e.contains("kein aktiver") {
                                eprintln!("[mining] Template-Fehler: {e}");
                            }
                        }
                    }
                }

                // ── Post-Block-Hooks für Gossip-Blöcke ───────────────────
                // Checkpoint-Prüfung
                if current_height > 0 && current_height % 100 == 0 {
                    let block = {
                        let chain = state.chain.lock().unwrap();
                        chain.blocks.last().cloned()
                    };
                    if let Some(block) = block {
                        Self::post_block_checkpoint(&state, &block).await;
                    }
                }
            }
        });
    }

    /// Öffentlicher Wrapper für alle Post-Block-Hooks.
    /// Wird vom Mining-Submit-Handler aufgerufen.
    pub fn run_post_block_hooks(state: &Arc<Self>, block: &Block) {
        Self::post_block_staking(state, block);
        Self::post_block_slashing(state, block);
        Self::post_block_reputation(state, block);
        Self::post_block_chat_policy(state, block, None);
    }

    /// Staking Epoch-Verarbeitung nach einem committed Block.
    fn post_block_staking(state: &Arc<Self>, block: &Block) {
        let mut pool = state.staking_pool.write().unwrap();

        // 1. Epoch-Rewards verteilen
        let reward_pool_balance = {
            let ledger = state.token_ledger.read().unwrap();
            ledger.balance("pool:storage_rewards")
        };
        let distributed = pool.process_epoch(block.index, reward_pool_balance);
        if distributed > rust_decimal::Decimal::ZERO {
            let mut ledger = state.token_ledger.write().unwrap();
            for (addr, entry) in &pool.stakers {
                if entry.pending_rewards > rust_decimal::Decimal::ZERO {
                    if let Err(e) = ledger.credit_staking_reward(addr, entry.pending_rewards) {
                        eprintln!("[staking] Reward-Gutschrift fehlgeschlagen: {e}");
                    }
                }
            }
            drop(ledger);
            for entry in pool.stakers.values_mut() {
                entry.pending_rewards = rust_decimal::Decimal::ZERO;
            }
        }

        // 2. Fällige Unstakes freigeben
        let matured = pool.drain_matured_unstakes();
        if !matured.is_empty() {
            let mut ledger = state.token_ledger.write().unwrap();
            for req in &matured {
                ledger.release_unstake_escrow(&req.address, req.amount);
            }
            if let Err(e) = ledger.persist() {
                eprintln!("[staking] Ledger-Persist nach Unstake-Release: {e}");
            }
        }

        // 3. StakingPool persistieren
        if distributed > rust_decimal::Decimal::ZERO || !matured.is_empty() {
            if let Err(e) = pool.persist() {
                eprintln!("[staking] Pool-Persist: {e}");
            }
        }
    }

    /// Slashing-Prüfung nach einem committed Block.
    ///
    /// 1. Markiert den Block-Signer als aktiv (Downtime-Tracker)
    /// 2. Entlässt Validatoren mit abgelaufener Jail-Zeit
    /// 3. Prüft alle aktiven Validatoren auf Downtime
    /// 4. Bei Double-Signing wird automatisch geslasht
    fn post_block_slashing(state: &Arc<Self>, block: &Block) {
        use crate::consensus::{
            SLASH_JAIL_DURATION_SECS,
        };

        let mut slash_store = state.slashing_store.write().unwrap();

        // 1. Block-Signer als aktiv markieren
        if !block.signer.is_empty() {
            slash_store.mark_active(&block.signer, block.index);
        }

        // 2. Abgelaufene Jails aufheben → Validator bleibt inaktiv (Cooldown)
        //    Muss sich durch einen PoW-Block beweisen um wieder aktiv zu werden.
        let released = slash_store.release_expired_jails();
        if !released.is_empty() {
            for vid in &released {
                println!("[slashing] 🔓 Validator '{}' aus Jail entlassen — bleibt inaktiv (Cooldown, muss durch Admin oder Stake re-aktiviert werden)", vid);
            }
        }

        // 3. Downtime-Check für alle aktiven Validatoren
        let validators: Vec<(String, Option<String>)> = {
            let vs = state.validator_set.read().unwrap();
            vs.validators.iter()
                .filter(|v| v.active)
                .filter(|v| v.node_id != block.signer) // Signer ist ja aktiv
                .map(|v| (v.node_id.clone(), None)) // wallet_address ist Optional
                .collect()
        };

        for (vid, _) in &validators {
            // Bereits gejailed? Dann nicht nochmal prüfen
            if slash_store.is_jailed(vid) {
                continue;
            }

            if let Some(offense) = slash_store.check_downtime(vid, block.index) {
                // Wallet-Adresse des Validators ermitteln (falls bekannt)
                let wallet_addr = Self::resolve_validator_wallet(state, vid);

                let slashed_amount = if let Some(ref wallet) = wallet_addr {
                    let mut pool = state.staking_pool.write().unwrap();
                    let stake = pool.stakers.get(wallet)
                        .map(|s| s.staked_amount)
                        .unwrap_or(rust_decimal::Decimal::ZERO);
                    let penalty = stake * rust_decimal::Decimal::from(offense.penalty_percent())
                        / rust_decimal::Decimal::from(100u64);
                    pool.slash(wallet, penalty)
                } else {
                    rust_decimal::Decimal::ZERO
                };

                let record = slash_store.record_slash(
                    vid,
                    wallet_addr.as_deref(),
                    offense,
                    slashed_amount,
                    block.index,
                );

                // Validator deaktivieren (Jail)
                {
                    let mut vs = state.validator_set.write().unwrap();
                    vs.set_active(vid, false);
                }

                eprintln!(
                    "[slashing] ⚠️  {} – {} STONE geslasht, Jail für {} Stunden",
                    record.offense.description(),
                    record.slashed_amount,
                    SLASH_JAIL_DURATION_SECS / 3600,
                );

                state.events.publish(NodeEvent::ValidatorSlashed {
                    validator_id: vid.clone(),
                    offense: record.offense.description(),
                    slashed_amount: record.slashed_amount.clone(),
                    timestamp: record.timestamp,
                });
            }
        }
    }

    /// Equivocation-Evidence → Slashing + Jail + Deaktivierung.
    ///
    /// Wird aus den P2P-Event-Handlern (master_server, stone_miner, setup)
    /// aufgerufen, wenn der `EquivocationTracker` einen Double-Sign erkennt.
    pub fn slash_equivocation(state: &Arc<Self>, evidence: &crate::consensus::EquivocationEvidence) {
        use crate::consensus::SlashingOffense;

        // Validator-NodeId via pub_key auflösen
        let (validator_id, wallet_addr) = {
            let vs = state.validator_set.read().unwrap();
            let found = vs.validators.iter().find(|v| v.public_key_hex == evidence.validator_pub_key);
            match found {
                Some(v) => (v.node_id.clone(), Self::resolve_validator_wallet(state, &v.node_id)),
                None => (evidence.validator_pub_key.clone(), None),
            }
        };

        let offense = SlashingOffense::DoubleSigning {
            block_index: evidence.block_index,
            hash_a: evidence.hash_a.clone(),
            hash_b: evidence.hash_b.clone(),
        };

        let slashed_amount = if let Some(ref wallet) = wallet_addr {
            let mut pool = state.staking_pool.write().unwrap();
            let stake = pool.stakers.get(wallet)
                .map(|s| s.staked_amount)
                .unwrap_or(rust_decimal::Decimal::ZERO);
            let penalty = stake * rust_decimal::Decimal::from(offense.penalty_percent())
                / rust_decimal::Decimal::from(100u64);
            pool.slash(wallet, penalty)
        } else {
            rust_decimal::Decimal::ZERO
        };

        let mut slash_store = state.slashing_store.write().unwrap();
        let record = slash_store.record_slash(
            &validator_id,
            wallet_addr.as_deref(),
            offense,
            slashed_amount,
            evidence.block_index,
        );
        drop(slash_store);

        // Validator deaktivieren
        {
            let mut vs = state.validator_set.write().unwrap();
            vs.set_active(&validator_id, false);
        }

        eprintln!(
            "[slashing] ⚠️  EQUIVOCATION SLASH: {} – {} STONE geslasht (Block #{}, hashes: {}…/{}…)",
            validator_id,
            record.slashed_amount,
            evidence.block_index,
            &evidence.hash_a[..12.min(evidence.hash_a.len())],
            &evidence.hash_b[..12.min(evidence.hash_b.len())],
        );

        state.events.publish(NodeEvent::ValidatorSlashed {
            validator_id,
            offense: record.offense.description(),
            slashed_amount: record.slashed_amount,
            timestamp: record.timestamp,
        });
    }

    /// Reputation-System nach einem committed Block aktualisieren.
    ///
    /// 1. Block-Signer als aktiven Node registrieren (falls noch nicht bekannt)
    /// 2. Heartbeat + Block-Signed für den Signer aufzeichnen
    /// 3. Alle Scores neu berechnen
    /// 4. Falls Distribution-Intervall erreicht: Pool ausschütten
    fn post_block_reputation(state: &Arc<Self>, block: &Block) {
        let mut registry = state.reputation_registry.write().unwrap();

        // 1. Block-Signer registrieren & Heartbeat
        if !block.signer.is_empty() {
            let signer_wallet = {
                // Wallet-Adresse des Signers ermitteln
                if block.signer == state.node_id {
                    let signing_key = load_or_create_validator_key();
                    local_validator_pubkey_hex(&signing_key)
                } else {
                    // Für Remote-Nodes: validator_pub_key aus dem Block verwenden
                    if !block.validator_pub_key.is_empty() {
                        block.validator_pub_key.clone()
                    } else {
                        block.signer.clone()
                    }
                }
            };
            registry.register_node(&block.signer, &signer_wallet);
            registry.record_heartbeat(&block.signer);
            registry.record_block_signed(&block.signer);
        }

        // 2. Scores aktualisieren
        registry.compute_all_scores();

        // 3. Distribution prüfen (alle 720 Blöcke)
        if registry.distribution_due(block.index) {
            let pool_balance = {
                let ledger = state.token_ledger.read().unwrap();
                ledger.balance(crate::token::reputation::NODE_OPERATOR_POOL)
            };

            let payouts = registry.calculate_distribution(pool_balance, block.index);
            if !payouts.is_empty() {
                let mut ledger = state.token_ledger.write().unwrap();
                let mut total_paid = rust_decimal::Decimal::ZERO;
                for (addr, amount) in &payouts {
                    if let Err(e) = ledger.credit_operator_reward(addr, *amount) {
                        eprintln!("[reputation] Reward-Gutschrift an {}… fehlgeschlagen: {e}",
                            &addr[..16.min(addr.len())]);
                    } else {
                        total_paid += amount;
                    }
                }
                if total_paid > rust_decimal::Decimal::ZERO {
                    println!(
                        "[reputation] 💰 Distribution Block #{}: {} STONE an {} Nodes verteilt",
                        block.index, total_paid, payouts.len()
                    );
                    if let Err(e) = ledger.persist() {
                        eprintln!("[reputation] Ledger-Persist nach Distribution: {e}");
                    }
                }
            }
        }

        // 4. Registry persistieren
        if let Err(e) = registry.persist() {
            eprintln!("[reputation] Registry-Persist: {e}");
        }
    }

    /// Chat-Policy nach einem committed Block: TTL-Tracking + GC + Report-Finalisierung.
    ///
    /// 1. Neue ChatMessage-TXs im Block → TTL-Eintrag erstellen
    /// 2. Garbage Collection: Abgelaufene Nachrichten-Content löschen
    /// 3. Pending Reports prüfen und ggf. finalisieren
    fn post_block_chat_policy(state: &Arc<Self>, block: &Block, chat_index: Option<&std::sync::Arc<std::sync::Mutex<crate::chat::ChatIndex>>>) {
        let mut policy = state.chat_policy.write().unwrap();

        // 1. Neue ChatMessage-TXs tracken
        for tx in &block.transactions {
            if tx.tx_type != TxType::ChatMessage {
                continue;
            }
            // msg_id und TTL aus Memo extrahieren
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&tx.memo) {
                let msg_id = data["msg_id"].as_str().unwrap_or("").to_string();
                if msg_id.is_empty() {
                    continue;
                }
                let ttl_str = data["ttl"].as_str().unwrap_or("30d");
                let ttl = crate::chat_policy::MessageTtl::from_str_or_default(ttl_str);

                policy.track_message(
                    &msg_id,
                    &tx.tx_id,
                    &tx.from,
                    &tx.to,
                    ttl,
                    tx.timestamp,
                    block.index,
                );
            }
        }

        // 2. Garbage Collection: Abgelaufene Nachrichten-Content löschen
        if let Some(chat_idx_arc) = chat_index {
            let mut chat_idx = chat_idx_arc.lock().unwrap();
            let purged = crate::chat_policy::gc_expired_messages(&mut policy, &mut chat_idx);
            if purged > 0 {
                crate::chat::save_chat_index(&chat_idx);
            }
        }

        // 3. Pending Reports finalisieren (Timeout etc.) – stake-gewichtet
        let stake_weights: std::collections::HashMap<String, rust_decimal::Decimal> = {
            let pool = state.staking_pool.read().unwrap();
            pool.stakers.iter()
                .filter(|(_, entry)| crate::token::StakeLevel::from_stake(entry.staked_amount).can_validate())
                .map(|(addr, entry)| (addr.clone(), entry.staked_amount))
                .collect()
        };
        let finalized = policy.finalize_all_pending(Some(&stake_weights));
        for (report_id, accepted, msg_id, reported_wallet) in &finalized {
            if *accepted {
                // Content im Chat-Index löschen
                if let Some(chat_idx_arc) = chat_index {
                    let mut chat_idx = chat_idx_arc.lock().unwrap();
                    crate::chat_policy::purge_message_content(&mut chat_idx, msg_id);
                    crate::chat::save_chat_index(&chat_idx);
                }

                // Slash
                let slash_amount = {
                    let pool = state.staking_pool.read().unwrap();
                    let staked = pool.stakers.get(reported_wallet)
                        .map(|s| s.staked_amount)
                        .unwrap_or(Decimal::ZERO);
                    staked * Decimal::from(crate::chat_policy::REPORT_SLASH_PCT)
                        / Decimal::from(100u32)
                };

                if slash_amount > Decimal::ZERO {
                    let mut pool = state.staking_pool.write().unwrap();
                    let actual = pool.slash(reported_wallet, slash_amount);
                    drop(pool);

                    let mut ledger = state.token_ledger.write().unwrap();
                    ledger.credit_to_operator_pool(actual);
                    let _ = ledger.persist();

                    println!(
                        "[chat-policy] ⚖️  Report {} auto-finalisiert: {} STONE geslasht",
                        &report_id[..8.min(report_id.len())], actual,
                    );
                }
            }
        }

        // Persistieren (wenn sich etwas geändert hat)
        let changed = policy.total_messages_tracked > 0 || !finalized.is_empty();
        if changed {
            if let Err(e) = policy.persist() {
                eprintln!("[chat-policy] Persist: {e}");
            }
        }
    }

    /// Versucht die Wallet-Adresse eines Validators aufzulösen.
    /// Sucht in der Node-Wallet-Konfiguration (gleiche node_id = gleiche wallet).
    fn resolve_validator_wallet(state: &Arc<Self>, validator_id: &str) -> Option<String> {
        // Wenn es unsere eigene Node ist
        if validator_id == state.node_id {
            return std::env::var("STONE_NODE_WALLET").ok();
        }
        // Für Remote-Validatoren: in der Trust-Registry nach wallet suchen
        // (Erweiterbar in Zukunft)
        None
    }

    /// Finality-Checkpoint nach einem committed Block erstellen (alle CHECKPOINT_INTERVAL Blöcke).
    async fn post_block_checkpoint(state: &Arc<Self>, block: &Block) {
        let should_create = {
            let store = state.checkpoint_store.read().unwrap();
            store.should_create_checkpoint(block.index)
        };
        if !should_create {
            return;
        }

        let required = {
            let vs = state.validator_set.read().unwrap();
            let active = vs.active_count();
            if active <= 1 { 1 } else { (active * 2) / 3 + 1 }
        };

        let mut checkpoint = crate::consensus::Checkpoint::new(
            block.index,
            block.hash.clone(),
            required,
        );

        // Lokal signieren
        let signing_key = load_or_create_validator_key();
        checkpoint.sign(&state.node_id, &signing_key);

        let finalized = checkpoint.is_finalized();
        {
            let mut store = state.checkpoint_store.write().unwrap();
            store.add_or_update(checkpoint.clone());
        }

        if finalized {
            println!(
                "[checkpoint] ✅ Block #{} finalisiert (single-node) – unwiderruflich",
                block.index
            );
        } else {
            println!(
                "[checkpoint] 📌 Checkpoint für Block #{} erstellt ({}/{} Signaturen, warte auf Peers)",
                block.index, 1, required
            );
        }

        // An Peers broadcasten (fire-and-forget, async)
        let peer_urls: Vec<String> = {
            let peers = state.peers.read().unwrap();
            peers.iter()
                .filter(|p| p.is_healthy())
                .map(|p| p.url.clone())
                .collect()
        };
        if !peer_urls.is_empty() {
            let cp_json = serde_json::to_vec(&checkpoint).unwrap_or_default();
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default();
            for peer in &peer_urls {
                let url = format!("{}/api/v1/checkpoint", peer.trim_end_matches('/'));
                match client.post(&url)
                    .header("Content-Type", "application/json")
                    .body(cp_json.clone())
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            println!("[checkpoint] → Checkpoint für #{} an {} gesendet", block.index, peer);
                        }
                    }
                    Err(e) => {
                        eprintln!("[checkpoint] Senden an {} fehlgeschlagen: {e}", peer);
                    }
                }
            }
        }
    }

    // ─── Web-of-Trust Methoden ────────────────────────────────────────────────

    /// Join-Anfrage eintragen (falls peer_id noch nicht bekannt)
    pub fn trust_request(
        &self,
        peer_id: String,
        public_key_hex: String,
        name: Option<String>,
    ) -> Result<(), String> {
        let mut reg = self.trust_registry.write().unwrap();
        if reg.iter().any(|e| e.peer_id == peer_id) {
            return Err(format!("peer_id '{peer_id}' bereits in der Trust-Registry"));
        }
        reg.push(TrustEntry::new(peer_id.clone(), public_key_hex, name.clone()));
        drop(reg);
        self.events.publish(NodeEvent::TrustJoinRequested {
            peer_id,
            name,
            timestamp: Utc::now().timestamp(),
        });
        Ok(())
    }

    /// Abstimmung: approve=true → Zustimmung, false → Ablehnung
    /// Gibt (neue_status, quorum_erreicht) zurück.
    pub fn trust_vote(
        &self,
        voter_peer_id: &str,
        target_peer_id: &str,
        approve: bool,
    ) -> Result<TrustStatus, String> {
        // Abstimmung ins History-Log schreiben
        {
            let mut history = self.trust_history.lock().unwrap();
            history.push(TrustVote {
                voter_peer_id: voter_peer_id.to_string(),
                target_peer_id: target_peer_id.to_string(),
                approve,
                timestamp: Utc::now().timestamp(),
            });
        }

        let mut reg = self.trust_registry.write().unwrap();
        let entry = reg
            .iter_mut()
            .find(|e| e.peer_id == target_peer_id)
            .ok_or_else(|| format!("peer_id '{target_peer_id}' nicht gefunden"))?;

        if entry.status == TrustStatus::Active && approve {
            // bereits aktiv – keine Änderung nötig
            return Ok(TrustStatus::Active);
        }

        // Doppelabstimmung desselben Voters verhindern
        entry.votes_approve.retain(|v| v != voter_peer_id);
        entry.votes_reject.retain(|v| v != voter_peer_id);

        if approve {
            entry.votes_approve.push(voter_peer_id.to_string());
        } else {
            entry.votes_reject.push(voter_peer_id.to_string());
        }

        // Quorum: Anzahl aktiver Validators als Referenz (min 1)
        let active_validators = {
            let vs = self.validator_set.read().unwrap();
            vs.validators.iter().filter(|v| v.active).count().max(1)
        };
        let threshold = (active_validators / 2) + 1;

        if entry.votes_approve.len() >= threshold {
            entry.status = TrustStatus::Active;
            entry.decided_at = Some(Utc::now().timestamp());
        } else if entry.votes_reject.len() >= threshold {
            entry.status = TrustStatus::Revoked;
            entry.decided_at = Some(Utc::now().timestamp());
        }

        let new_status = entry.status.clone();
        let votes_for = entry.votes_approve.len();
        let votes_against = entry.votes_reject.len();
        drop(reg);

        // WS-Event emittieren
        let now = Utc::now().timestamp();
        match new_status {
            TrustStatus::Active => {
                self.events.publish(NodeEvent::TrustApproved {
                    peer_id: target_peer_id.to_string(),
                    voter: voter_peer_id.to_string(),
                    votes_for,
                    timestamp: now,
                });
            }
            TrustStatus::Revoked => {
                self.events.publish(NodeEvent::TrustRevoked {
                    peer_id: target_peer_id.to_string(),
                    voter: voter_peer_id.to_string(),
                    votes_against,
                    timestamp: now,
                });
            }
            TrustStatus::Pending => {
                self.events.publish(NodeEvent::TrustVoteCast {
                    peer_id: target_peer_id.to_string(),
                    voter: voter_peer_id.to_string(),
                    approve,
                    votes_for,
                    votes_against,
                    needed: threshold,
                    timestamp: now,
                });
            }
        }

        Ok(new_status)
    }

    /// Zusammenfassung für NodeStatusResponse
    pub fn trust_summary(&self) -> TrustSummary {
        let reg = self.trust_registry.read().unwrap();
        TrustSummary {
            active: reg.iter().filter(|e| e.status == TrustStatus::Active).count(),
            pending: reg.iter().filter(|e| e.status == TrustStatus::Pending).count(),
            revoked: reg.iter().filter(|e| e.status == TrustStatus::Revoked).count(),
        }
    }

    /// Gibt alle Pending-Einträge zurück
    pub fn trust_pending(&self) -> Vec<TrustEntry> {
        self.trust_registry
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.status == TrustStatus::Pending)
            .cloned()
            .collect()
    }

    /// Gibt die Abstimmungshistorie zurück
    pub fn trust_history_snapshot(&self) -> Vec<TrustVote> {
        self.trust_history.lock().unwrap().clone()
    }

    /// Prüft ob eine peer_id aktiv vertrauenswürdig ist
    pub fn is_trusted(&self, peer_id: &str) -> bool {
        self.trust_registry
            .read()
            .unwrap()
            .iter()
            .any(|e| e.peer_id == peer_id && e.status == TrustStatus::Active)
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

impl From<&Block> for BlockResponse {
    fn from(b: &Block) -> Self {
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
