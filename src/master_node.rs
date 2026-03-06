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
    BlockProposal, CheckpointStore, PreCommitRequest, SlashingStore, ValidatorSet,
    VoteMessage, VotePhase, VotingRound,
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

/// Block-Intervall in Sekunden (wie oft ein neuer Block erzeugt wird)
pub const MINING_INTERVAL_SECS: u64 = 30;

/// Initialer Block-Reward in STONE (vor erstem Halving)
pub const INITIAL_BLOCK_REWARD: &str = "10.0";

/// Alle N Blöcke halbiert sich der Reward
/// 210.000 Blöcke × 30s = ~72.9 Tage pro Halving-Epoche
pub const HALVING_INTERVAL: u64 = 210_000;

/// Maximale Supply (aus Genesis-Config, hier als Fallback)
pub const MAX_SUPPLY: &str = "50000000";

/// Minimaler Block-Reward (unter diesem Wert wird nicht mehr gemined)
pub const MIN_BLOCK_REWARD: &str = "0.00000001";

/// Timeout für Peer-Voting in Sekunden (Multi-Node-Konsensus)
pub const VOTE_TIMEOUT_SECS: u64 = 10;

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
    /// Kanal um geminete Blöcke an das P2P-Netzwerk zu broadcasten.
    /// Wird von setup.rs gesetzt nachdem das Netzwerk gestartet ist.
    pub block_broadcast_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Block>>>,
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
}

impl MasterNodeState {
    pub fn new(node_id: String, cluster_key: String, role: NodeRole) -> Arc<Self> {
        let chain = StoneChain::load_or_create(&cluster_key);

        // Token-Ledger laden oder aus Chain rekonstruieren
        let mut ledger = TokenLedger::load();
        if ledger.total_supply() == rust_decimal::Decimal::ZERO && chain.blocks.len() > 0 {
            // Versuche Rebuild aus Chain (falls DB fehlt, aber Chain TXs hat)
            ledger = TokenLedger::rebuild_from_chain(&chain.blocks);
        } else {
            // Replay-Schutz: processed_txs aus Chain rekonstruieren
            // (wird nicht in RocksDB persistiert, muss nach jedem Start geladen werden)
            ledger.rebuild_processed_txs(&chain.blocks);
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
        let staking_pool = crate::token::StakingPool::load();
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
            staking_pool: RwLock::new(staking_pool),
            shard_registry: ShardHolderRegistry::new(),
            checkpoint_store: RwLock::new(CheckpointStore::load()),
            slashing_store: RwLock::new(SlashingStore::load()),
            reputation_registry: RwLock::new(reputation_registry),
            chat_policy: RwLock::new(chat_policy),
            mining_wallet: RwLock::new(Self::load_mining_wallet()),
            pending_challenge_responses: Mutex::new(Vec::new()),
            block_broadcast_tx: Mutex::new(None),
        });

        // Wenn die Chain bereits > 10 Blöcke hat (Restart einer synced Node),
        // Mining sofort erlauben (kein Initial-Sync nötig)
        {
            let chain_len = state.chain.lock().unwrap().blocks.len();
            if chain_len > 10 {
                state.metrics.initial_sync_done.store(true, Ordering::Relaxed);
                println!("[mining] Chain hat {chain_len} Blöcke – Initial-Sync übersprungen");
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
                let info = ValidatorInfo::new(node_id.clone(), pub_key_hex.clone());
                vs.add(info);
                println!(
                    "[consensus] ✅ Node '{}' als Validator registriert (Wallet: {}…)",
                    &node_id,
                    &pub_key_hex[..16.min(pub_key_hex.len())]
                );
            } else {
                println!(
                    "[consensus] Validator '{}' bereits registriert",
                    &node_id
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

        // Wallet-Map: Momentan kennen wir nur unsere eigene Wallet
        // In Zukunft wird hier die Trust-Registry/P2P-Handshake-Info genutzt
        let mut wallet_map = HashMap::new();
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

    /// Peers lesen
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().unwrap().clone()
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
                Err(e)
            }
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

        // ── PoA-Check: Ist diese Node der ausgewählte Validator? ──────────
        // Lock-Ordnung: chain zuerst (Daten cachen) → drop → dann validator_set
        let (chain_next_index, chain_prev_hash) = {
            let chain = self.chain.lock().unwrap();
            let idx = chain.blocks.len() as u64;
            let hash = chain.blocks.last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".into());
            (idx, hash)
        };
        {
            let vs = self.validator_set.read().unwrap();
            if !vs.validators.is_empty() {
                if !vs.is_active_validator(&self.node_id) {
                    return Err("Mining: Node ist kein aktiver Validator".into());
                }

                let (stakes, jailed, wallet_map) = self.build_selection_context();

                if !vs.is_selected_validator_weighted(&self.node_id, &chain_prev_hash, chain_next_index, &stakes, &jailed, &wallet_map) {
                    let selected = vs.select_validator_weighted(&chain_prev_hash, chain_next_index, &stakes, &jailed, &wallet_map)
                        .map(|v| v.node_id.clone())
                        .unwrap_or_else(|| "?".into());
                    return Err(format!(
                        "Mining: Node '{}' nicht ausgewählt für Block #{chain_next_index} (→ '{selected}')",
                        self.node_id
                    ));
                }
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

        // Prüfe ob es Pending-Challenge-Responses gibt (rechtfertigt einen Block auch ohne User-TXs)
        let has_pending_responses = !self.pending_challenge_responses.lock().unwrap().is_empty();

        // Leere Blöcke vermeiden: nur Reward-TX ohne User-TXs oder Challenge-Responses → überspringen.
        // Das verhindert, dass die Chain alle 30s mit leeren Blöcken aufgebläht wird.
        if !has_user_txs && !has_pending_responses {
            // Reward-TX wieder zurücknehmen — sie wird beim nächsten sinnvollen Block erstellt
            return Err("Mining: Keine User-TXs oder Challenge-Responses – Block übersprungen".into());
        }

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
                    let mut challenge_rewards_total = Decimal::ZERO;
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

                // Block-Hash neu berechnen (weil storage_challenges den Hash beeinflusst)
                block.hash = crate::blockchain::calculate_hash(&block);
                block.signature = crate::blockchain::sign_hash(&self.cluster_key, &block.hash);
                let new_sig = sign_block(&signing_key, &block.hash);
                block.validator_signature = new_sig;
            }
        }

        println!(
            "[mining] ⛏️  Block #{} vorbereitet – {} TXs, Reward: {} STONE → {}",
            block.index,
            block.transactions.len(),
            reward_amount,
            &reward_wallet[..16.min(reward_wallet.len())],
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
            let receipts = ledger.apply_block_txs(&block.transactions, block.index);
            ledger.set_current_validator(None);

            // ── Staking-TXs im StakingPool verarbeiten ────────────────────
            {
                let mut pool = self.staking_pool.write().unwrap();
                for tx in &block.transactions {
                    match tx.tx_type {
                        TxType::Stake => {
                            if let Err(e) = pool.stake(&tx.from, tx.amount) {
                                eprintln!("[staking] Stake fehlgeschlagen für {}: {e}", &tx.from[..12.min(tx.from.len())]);
                            }
                        }
                        TxType::Unstake => {
                            if let Err(e) = pool.request_unstake(&tx.from, tx.amount) {
                                eprintln!("[staking] Unstake fehlgeschlagen für {}: {e}", &tx.from[..12.min(tx.from.len())]);
                            }
                        }
                        _ => {}
                    }
                }
            }

            if !receipts.is_empty() {
                if let Err(e) = ledger.persist() {
                    eprintln!("[mining] Ledger-Persistierung nach Block #{} fehlgeschlagen: {e}", block.index);
                }
            }
        }

        // Block wurde bereits durch commit_block() → persist_last_block() persistiert.

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

        // ── Auto-Snapshot (alle SNAPSHOT_INTERVAL Blöcke) ─────────────────
        if crate::snapshot::should_create_snapshot(block.index) {
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

    /// Hintergrund-Task: Block-Mining alle `MINING_INTERVAL_SECS` Sekunden.
    ///
    /// Der Mining-Loop:
    /// 1. Prüft ob seit dem letzten Block genug Zeit vergangen ist
    /// 2. Prüft PoA-Berechtigung
    /// 3. Erstellt einen neuen Block mit Reward-TX + Mempool-TXs
    /// 4. Schläft bis zum nächsten Intervall
    pub fn start_mining_loop(state: Arc<Self>) {
        let interval = Duration::from_secs(MINING_INTERVAL_SECS);
        println!(
            "[mining] ⛏️  Mining-Loop gestartet (Intervall: {}s, Reward: {} STONE, Halving: alle {} Blöcke)",
            MINING_INTERVAL_SECS, INITIAL_BLOCK_REWARD, HALVING_INTERVAL
        );

        tokio::spawn(async move {
            // Erste Wartezeit: halbes Intervall (damit nicht sofort nach Start)
            tokio::time::sleep(Duration::from_secs(MINING_INTERVAL_SECS / 2)).await;

            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                // ── Initial-Sync abwarten ─────────────────────────────────
                // Erst nach abgeschlossenem Peer-Sync starten, damit keine
                // Fork-Blöcke erzeugt werden. Timeout: 60s nach Node-Start.
                if !state.metrics.initial_sync_done.load(Ordering::Relaxed) {
                    let uptime = Utc::now().timestamp() - state.started_at;
                    if uptime < 60 {
                        continue; // Warte auf Sync
                    }
                    // Timeout: kein Peer hat mehr Blöcke oder kein Peer verbunden
                    println!("[mining] ⏰ Initial-Sync Timeout (60s) – starte Mining");
                    state.metrics.initial_sync_done.store(true, Ordering::Relaxed);

                    // Token-Ledger vollständig aus der (jetzt synced) Chain neu aufbauen.
                    // Während des P2P-Sync konnten TXs wegen falscher Nonce-Reihenfolge
                    // übersprungen worden sein – der Rebuild korrigiert das.
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

                // Mining-Throttle: Leistungsbegrenzung prüfen
                {
                    let throttle = state.metrics.mining_throttle_pct.load(Ordering::Relaxed);
                    if throttle == 0 {
                        continue; // Mining komplett deaktiviert
                    }
                    if throttle < 100 {
                        // Probabilistisches Throttling: Block mit (100-throttle)% überspringen
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};
                        let now = Utc::now().timestamp_millis() as u64;
                        let mut hasher = DefaultHasher::new();
                        now.hash(&mut hasher);
                        let roll = hasher.finish() % 100;
                        if roll >= throttle {
                            continue; // Throttled – diesen Block überspringen
                        }
                    }
                }

                // Prüfen ob der letzte Block alt genug ist (verhindert Doppel-Blocks
                // wenn commit_documents kurz vorher einen Block erstellt hat)
                {
                    let chain = state.chain.lock().unwrap();
                    if let Some(last) = chain.blocks.last() {
                        let age = Utc::now().timestamp() - last.timestamp;
                        if age < (MINING_INTERVAL_SECS as i64 / 2) {
                            continue; // Zu früh – letzter Block noch frisch
                        }
                    }
                }

                // Mempool: abgelaufene TXs bereinigen
                let evicted = state.mempool.evict_expired();
                if evicted > 0 {
                    println!("[mining] 🧹 {} abgelaufene TXs aus Mempool entfernt", evicted);
                }

                // ── Hybrid Consensus: Single-Node vs. Multi-Node ──────────
                let active_validators = {
                    let vs = state.validator_set.read().unwrap();
                    vs.active_count()
                };

                if active_validators <= 1 {
                    // ═══ SINGLE-NODE MODUS: Sofort committen (wie bisher) ═══
                    match state.mint_block() {
                        Ok(block) => {
                            // Committete Challenge-Responses aus Pending-Buffer entfernen
                            let committed_ids: Vec<String> = block.challenge_responses
                                .iter().map(|r| r.challenge_id.clone()).collect();
                            state.clear_committed_responses(&committed_ids);

                            Self::post_block_staking(&state, &block);
                            Self::post_block_slashing(&state, &block);
                            Self::post_block_reputation(&state, &block);
                            Self::post_block_chat_policy(&state, &block, None);
                            Self::post_block_checkpoint(&state, &block).await;

                            // ── Block via P2P-Gossipsub an alle Peers senden ──
                            {
                                let tx = state.block_broadcast_tx.lock().unwrap();
                                if let Some(ref sender) = *tx {
                                    let _ = sender.send(block.clone());
                                }
                            }

                            let _ = block;
                        }
                        Err(e) => {
                            if !e.contains("nicht ausgewählt") && !e.contains("kein aktiver") {
                                eprintln!("[mining] {e}");
                            }
                        }
                    }
                } else {
                    // ═══ MULTI-NODE MODUS: Proposal → Voting → Commit ═══
                    match state.prepare_mining_block() {
                        Ok(block) => {
                            let round = state.round_counter.fetch_add(1, Ordering::Relaxed);
                            let signing_key = load_or_create_validator_key();
                            let proposal = BlockProposal::new(
                                block.clone(),
                                state.node_id.clone(),
                                &signing_key,
                                round,
                            );

                            println!(
                                "[consensus] 📤 Proposal für Block #{} gesendet (Runde {}, {} aktive Validators)",
                                block.index, round, active_validators,
                            );

                            // ── Phase 1: Pre-Vote ──────────────────────────────
                            // Eigene Pre-Vote: Auto-Accept
                            let own_vote = VoteMessage::new_with_phase(
                                round,
                                block.hash.clone(),
                                state.node_id.clone(),
                                true,
                                &signing_key,
                                String::new(),
                                VotePhase::PreVote,
                            );

                            // VotingRound starten (Phase 1: PreVote)
                            {
                                let vs = state.validator_set.read().unwrap();
                                let mut voting = state.active_voting.lock().unwrap();
                                let mut vr = VotingRound::new(round, block.hash.clone(), state.node_id.clone());
                                let _ = vr.add_pre_vote(own_vote, &vs);
                                *voting = Some(vr);
                            }

                            // Proposal an alle Healthy Peers senden → Pre-Votes sammeln
                            let peer_urls: Vec<String> = {
                                let peers = state.peers.read().unwrap();
                                peers.iter()
                                    .filter(|p| p.is_healthy())
                                    .map(|p| p.url.clone())
                                    .collect()
                            };

                            let proposal_json = serde_json::to_vec(&proposal).unwrap_or_default();
                            let client = reqwest::Client::builder()
                                .timeout(Duration::from_secs(VOTE_TIMEOUT_SECS))
                                .danger_accept_invalid_certs(true)
                                .build()
                                .unwrap_or_default();

                            for peer_url in &peer_urls {
                                let url = format!("{}/api/v1/p2p/proposal", peer_url.trim_end_matches('/'));
                                match client.post(&url)
                                    .header("Content-Type", "application/json")
                                    .body(proposal_json.clone())
                                    .send()
                                    .await
                                {
                                    Ok(resp) => {
                                        if let Ok(val) = resp.json::<serde_json::Value>().await {
                                            if let Ok(vote) = serde_json::from_value::<VoteMessage>(
                                                val.get("vote").cloned().unwrap_or_default()
                                            ) {
                                                let vs = state.validator_set.read().unwrap();
                                                let mut voting = state.active_voting.lock().unwrap();
                                                if let Some(ref mut vr) = *voting {
                                                    if let Err(e) = vr.add_pre_vote(vote.clone(), &vs) {
                                                        eprintln!("[consensus] PreVote von {} ungültig: {e}", peer_url);
                                                    } else {
                                                        println!(
                                                            "[consensus] 🗳️  PreVote von '{}': {}",
                                                            vote.voter_id,
                                                            if vote.accept { "✅ Accept" } else { "❌ Reject" }
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[consensus] Proposal an {} fehlgeschlagen: {e}", peer_url);
                                    }
                                }
                            }

                            // Phase 1 auswerten: ⅔+1 Pre-Votes?
                            let (prevote_quorum, prevote_info) = {
                                let vs = state.validator_set.read().unwrap();
                                let voting = state.active_voting.lock().unwrap();
                                if let Some(ref vr) = *voting {
                                    let tally = vr.tally_pre_votes(&vs);
                                    let info = format!(
                                        "{}/{} PreVote-Accept, {}/{} nötig",
                                        tally.accepts, tally.total_validators,
                                        tally.threshold, tally.total_validators,
                                    );
                                    (tally.quorum_reached, info)
                                } else {
                                    (false, "Keine Voting-Runde".into())
                                }
                            };

                            if !prevote_quorum {
                                println!(
                                    "[consensus] ❌ Kein PreVote-Quorum ({}) – Block #{} verworfen",
                                    prevote_info, block.index,
                                );
                                for tx in &block.transactions {
                                    if tx.tx_type != TxType::Reward && tx.tx_type != TxType::Memorial {
                                        let _ = state.mempool.add_tx(tx.clone(), None);
                                    }
                                }
                                *state.active_voting.lock().unwrap() = None;
                                continue;
                            }

                            println!(
                                "[consensus] ✅ PreVote-Quorum erreicht ({}) – starte PreCommit-Phase",
                                prevote_info,
                            );

                            // ── Phase 2: Pre-Commit ────────────────────────────
                            // Übergang zur PreCommit-Phase + PreCommitRequest bauen
                            let pre_commit_request = {
                                let mut voting = state.active_voting.lock().unwrap();
                                if let Some(ref mut vr) = *voting {
                                    let req = PreCommitRequest {
                                        round: vr.round,
                                        block_hash: vr.block_hash.clone(),
                                        proposer_id: vr.proposer_id.clone(),
                                        pre_votes: vr.collected_pre_votes(),
                                    };
                                    vr.advance_to_precommit();
                                    // Eigene Pre-Commit: Auto-Accept
                                    let own_pc = VoteMessage::new_with_phase(
                                        round,
                                        block.hash.clone(),
                                        state.node_id.clone(),
                                        true,
                                        &signing_key,
                                        String::new(),
                                        VotePhase::PreCommit,
                                    );
                                    let vs = state.validator_set.read().unwrap();
                                    let _ = vr.add_pre_commit(own_pc, &vs);
                                    Some(req)
                                } else {
                                    None
                                }
                            };

                            if let Some(pcr) = pre_commit_request {
                                let pcr_json = serde_json::to_vec(&pcr).unwrap_or_default();

                                for peer_url in &peer_urls {
                                    let url = format!("{}/api/v1/p2p/precommit", peer_url.trim_end_matches('/'));
                                    match client.post(&url)
                                        .header("Content-Type", "application/json")
                                        .body(pcr_json.clone())
                                        .send()
                                        .await
                                    {
                                        Ok(resp) => {
                                            if let Ok(val) = resp.json::<serde_json::Value>().await {
                                                if let Ok(vote) = serde_json::from_value::<VoteMessage>(
                                                    val.get("vote").cloned().unwrap_or_default()
                                                ) {
                                                    let vs = state.validator_set.read().unwrap();
                                                    let mut voting = state.active_voting.lock().unwrap();
                                                    if let Some(ref mut vr) = *voting {
                                                        if let Err(e) = vr.add_pre_commit(vote.clone(), &vs) {
                                                            eprintln!("[consensus] PreCommit von {} ungültig: {e}", peer_url);
                                                        } else {
                                                            println!(
                                                                "[consensus] 🔒 PreCommit von '{}': {}",
                                                                vote.voter_id,
                                                                if vote.accept { "✅ Commit" } else { "❌ Reject" }
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[consensus] PreCommit-Anfrage an {} fehlgeschlagen: {e}", peer_url);
                                        }
                                    }
                                }
                            }

                            // Phase 2 finalisieren: ⅔+1 Pre-Commits?
                            let (quorum_reached, tally_info) = {
                                let vs = state.validator_set.read().unwrap();
                                let mut voting = state.active_voting.lock().unwrap();
                                if let Some(ref mut vr) = *voting {
                                    let tally = vr.finalize(&vs);
                                    let info = format!(
                                        "{}/{} PreCommit-Accept, {}/{} nötig",
                                        tally.accepts, tally.total_validators,
                                        tally.threshold, tally.total_validators,
                                    );
                                    (tally.quorum_reached, info)
                                } else {
                                    (false, "Keine Voting-Runde".into())
                                }
                            };

                            if quorum_reached {
                                println!(
                                    "[consensus] ✅ 2-Phase BFT Quorum erreicht ({}) – Block #{} wird committed",
                                    tally_info, block.index,
                                );
                                match state.commit_mining_block(block.clone()) {
                                    Ok(()) => {
                                        // Committete Challenge-Responses aus Pending-Buffer entfernen
                                        let committed_ids: Vec<String> = block.challenge_responses
                                            .iter().map(|r| r.challenge_id.clone()).collect();
                                        state.clear_committed_responses(&committed_ids);

                                        Self::post_block_staking(&state, &block);
                                        Self::post_block_slashing(&state, &block);
                                        Self::post_block_reputation(&state, &block);
                                        Self::post_block_chat_policy(&state, &block, None);
                                        Self::post_block_checkpoint(&state, &block).await;

                                        // ── Block via P2P-Gossipsub broadcasten ──
                                        {
                                            let tx = state.block_broadcast_tx.lock().unwrap();
                                            if let Some(ref sender) = *tx {
                                                let _ = sender.send(block.clone());
                                            }
                                        }
                                    }
                                    Err(e) => eprintln!("[consensus] Commit fehlgeschlagen: {e}"),
                                }
                            } else {
                                println!(
                                    "[consensus] ❌ Kein PreCommit-Quorum ({}) – Block #{} verworfen",
                                    tally_info, block.index,
                                );
                                // TXs zurück in den Mempool (außer Reward + Memorial)
                                for tx in &block.transactions {
                                    if tx.tx_type != TxType::Reward && tx.tx_type != TxType::Memorial {
                                        let _ = state.mempool.add_tx(tx.clone(), None);
                                    }
                                }
                            }

                            // Voting-Runde aufräumen
                            *state.active_voting.lock().unwrap() = None;
                        }
                        Err(e) => {
                            if !e.contains("nicht ausgewählt") && !e.contains("kein aktiver") {
                                eprintln!("[mining] {e}");
                            }
                        }
                    }
                }
            }
        });
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

        // 2. Abgelaufene Jails aufheben → Validator re-aktivieren
        let released = slash_store.release_expired_jails();
        if !released.is_empty() {
            let mut vs = state.validator_set.write().unwrap();
            for vid in &released {
                vs.set_active(vid, true);
                println!("[slashing] 🔓 Validator '{}' aus Jail entlassen, re-aktiviert", vid);
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

        // 3. Pending Reports finalisieren (Timeout etc.)
        let finalized = policy.finalize_all_pending();
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
