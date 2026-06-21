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
//! Blöcke halbiert sich der Reward. Mining stoppt wenn `pool:mining_rewards` leer ist.

pub mod miner_registry;
pub mod mining;
pub mod post_block;
pub mod trust;
pub mod types;

pub use miner_registry::{
    AutoMiningConfig, BlockTimer, MinerConnectMsg, MinerHeartbeat, MinerIdentity, MinerRegistry,
};
pub use types::*;

use crate::blockchain::{Block, Document, DocumentTombstone, NodeRole, StoneChain};
use crate::consensus::{
    load_or_create_validator_key, local_validator_pubkey_hex, sign_block,
    CheckpointStore, EquivocationTracker, SlashingStore,
    ValidatorSet, VotingRound,
};
use crate::shard::ShardHolderRegistry;
use crate::chat_policy::ChatPolicyStore;
use crate::token::{Mempool, TokenLedger, ReputationRegistry};
use crate::token::transaction::{TokenTx, TxType};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;



/// Ziel-Block-Zeit in Sekunden (Competitive PoW).
/// 30s = schnelle Blöcke, Difficulty wird dynamisch angepasst.
pub const TARGET_BLOCK_TIME_SECS: u64 = crate::consensus::TARGET_BLOCK_TIME_SECS;

/// Legacy: Block-Intervall in Sekunden (für Kompatibilität mit altem Code).
/// Wird durch TARGET_BLOCK_TIME_SECS ersetzt.
pub const MINING_INTERVAL_SECS: u64 = TARGET_BLOCK_TIME_SECS;

/// Initialer Block-Reward in STONE (vor erstem Halving)
pub const INITIAL_BLOCK_REWARD: &str = "7.0";

/// Alle N Blöcke halbiert sich der Reward
/// 2.102.400 Blöcke × 30s = ~2 Jahre pro Halving-Epoche
pub const HALVING_INTERVAL: u64 = 2_102_400;

/// Maximale Supply (aus Genesis-Config, hier als Fallback)
pub const MAX_SUPPLY: &str = "55000000";

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
    pub peer_id: Option<String>,
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
            peer_id: None,
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
    /// Governance: Trusted Node Registry, Proposals, Dual-Voting, Multisig
    pub governance: RwLock<crate::token::GovernanceStore>,
    /// Gaming-Economy: Game-Wallets, NFT-Items, Marktplatz, Sessions
    pub game_economy: RwLock<crate::token::GameEconomyStore>,
    /// Testnet-Markt-Simulator: Simulierter Coin-Kurs (nur im Testnet aktiv).
    /// Entfernen: Dieses Feld + post_block_market_sim() + API-Handler löschen.
    pub testnet_market: RwLock<crate::token::TestnetMarket>,
    /// HTLC Store: Hash Time-Locked Contracts für Atomic Swaps
    pub htlc_store: RwLock<crate::token::HtlcStore>,
    /// Bridge Store: Wrapped Token Bridge für Cross-Chain Transfers
    pub bridge_store: RwLock<crate::token::BridgeStore>,

    /// SQLite-Datenbank (ersetzt JSON-Dateien für users, orgs, peers, trust, etc.)
    pub db: crate::database::Database,

    /// Laufzeit-Config für Auto-Mining / BlockTimer.
    pub auto_mining_config: AutoMiningConfig,
    /// Registry aller aktiven externen Miner (Heartbeat-basiert).
    pub miner_registry: RwLock<MinerRegistry>,
    /// Auto-Block-Timer (120 s Default wenn keine Miner aktiv).
    pub block_timer: Mutex<BlockTimer>,

    // ─── Caches (Performance: vermeidet teure Berechnungen bei jedem API-Request) ───
    /// Gecachte Chain-Zusammenfassung (wird bei jedem neuen Block aktualisiert)
    pub cached_summary: RwLock<Option<ChainSummary>>,
    /// Gecachte Dateiordner-Größe in Bytes (wird periodisch aktualisiert, nicht per Request)
    pub cached_data_dir_bytes: AtomicU64,
    /// Gecachte Memory-RSS in KB (wird periodisch aktualisiert)
    pub cached_memory_rss_kb: AtomicU64,
    /// Gecachte CPU-Time in ms (wird periodisch aktualisiert)
    pub cached_cpu_time_ms: AtomicU64,
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

        // Token-DB einmalig öffnen (Column Families)
        if let Err(e) = crate::token::init_token_db() {
            eprintln!("[token-db] ⚠️  init_token_db fehlgeschlagen: {e}");
        }

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
                    if let Err(e) = ledger.persist() {
                        eprintln!("[token] ⚠️  Persist nach Sync-Marker-Reset fehlgeschlagen: {e}");
                    }
                }
                if let Ok(db) = crate::token::open_token_db() {
                    if let Err(e) = db.put(b"__mig_ledger_repair_v3", b"done") {
                        eprintln!("[token] ⚠️  Migration-Marker v3 schreiben fehlgeschlagen: {e}");
                    }
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
        // Idempotente Migration: Gaming-Pool (45M) für bestehende Chains.
        if let Err(e) = crate::token::migrate_pool_gaming(&mut ledger) {
            eprintln!("[token] ⚠️  Gaming-Pool Migration fehlgeschlagen: {e}");
        }
        // Idempotenter Unlock: Gaming-Pool → Foundation-Wallet (falls Mnemonic gesetzt).
        if let Err(e) = crate::token::unlock_gaming_pool_to_foundation(&mut ledger) {
            eprintln!("[token] ⚠️  Gaming-Pool Unlock fehlgeschlagen: {e}");
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
        let db = crate::database::Database::open()
            .unwrap_or_else(|e| panic!("Datenbank konnte nicht geöffnet werden: {e}"));
        println!("[db] SQLite-Datenbank geöffnet: stone_data/stone.db");

        // Einmalige Migration von JSON → SQLite
        db.migrate_from_json_files();

        // Globaler DB-Pointer setzen — alle Persistenz-Funktionen schreiben jetzt parallel
        crate::database::set_global_db(db.clone());

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
            governance: RwLock::new(crate::token::GovernanceStore::load()),
            game_economy: RwLock::new(crate::token::GameEconomyStore::load()),
            testnet_market: RwLock::new(crate::token::TestnetMarket::load_or_default()),
            htlc_store: RwLock::new(crate::token::HtlcStore::load()),
            bridge_store: RwLock::new(crate::token::BridgeStore::load()),
            db,
            auto_mining_config: {
                let c = AutoMiningConfig::load();
                println!(
                    "[auto-mining] enabled={}, timeout={}s, hb_timeout={}s, partial_delta={}",
                    c.enabled, c.auto_timeout_secs, c.heartbeat_timeout_secs, c.heartbeat_partial_delta,
                );
                c
            },
            miner_registry: {
                let c = AutoMiningConfig::load();
                RwLock::new(MinerRegistry::new(c.heartbeat_timeout_secs))
            },
            block_timer: {
                let c = AutoMiningConfig::load();
                Mutex::new(BlockTimer::new(c.auto_timeout_secs, c.enabled))
            },
            cached_summary: RwLock::new(None),
            cached_data_dir_bytes: AtomicU64::new(0),
            cached_memory_rss_kb: AtomicU64::new(0),
            cached_cpu_time_ms: AtomicU64::new(0),
        });

        // HTLC-Store aus Chain-Daten rekonstruieren falls leer
        {
            let needs_rebuild = state.htlc_store.read()
                .unwrap_or_else(|e| e.into_inner())
                .list_all().is_empty();
            if needs_rebuild {
                // Sammle alle HTLC-TXs aus der Chain
                let htlc_blocks: Vec<(Vec<TokenTx>, u64)> = {
                    let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                    chain.blocks.iter()
                        .filter_map(|block| {
                            let htlc_txs: Vec<_> = block.transactions.iter()
                                .filter(|tx| matches!(tx.tx_type, TxType::HtlcCreate | TxType::HtlcClaim | TxType::HtlcRefund))
                                .cloned()
                                .collect();
                            if htlc_txs.is_empty() { None } else { Some((htlc_txs, block.index)) }
                        })
                        .collect()
                };
                if !htlc_blocks.is_empty() {
                    let total: usize = htlc_blocks.iter().map(|(txs, _)| txs.len()).sum();
                    for (txs, idx) in &htlc_blocks {
                        Self::process_htlc_txs(&state, txs, *idx);
                    }
                    println!("[htlc] 🔄 {} HTLC-TXs aus {} Blöcken rekonstruiert", total, htlc_blocks.len());
                }
            }
        }

        // Nach Restart: Prüfen ob die lokale Chain aktuell genug ist.
        // Wenn der letzte Block jünger als 3 Mining-Intervalle (6 Min) ist,
        // war die Node erst kürzlich online und kann sofort minen.
        // Ansonsten: Initial-Sync abwarten (max 240s), damit wir nicht
        // auf einem veralteten Fork minen.
        {
            let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
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
            let mut vs = state.validator_set.write().unwrap_or_else(|e| e.into_inner());
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

        // SECURITY P0: Keine implizite Validator-Admission aus historischer Chain.
        // ValidatorSet-Mutationen müssen explizit über Governance/Admin erfolgen.

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
            let pool = self.staking_pool.read().unwrap_or_else(|e| e.into_inner());
            pool.stakers.iter()
                .map(|(addr, entry)| (addr.clone(), entry.staked_amount))
                .collect()
        };

        // Jailed aus SlashingStore:
        // Slashing kann kanonisch per PubKey oder legacy per node_id gespeichert sein.
        // Für Konsens-Checks wird auf node_id normalisiert.
        let jailed_raw: std::collections::HashSet<String> = {
            let ss = self.slashing_store.read().unwrap_or_else(|e| e.into_inner());
            ss.jailed.keys().cloned().collect()
        };

        let jailed: std::collections::HashSet<String> = {
            let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
            let mut out = std::collections::HashSet::new();

            // Legacy: node_id-basierte Jails direkt übernehmen.
            for id in &jailed_raw {
                out.insert(id.clone());
            }

            // Canonical: PubKey-basierte Jails auf node_id zurückführen.
            for v in &vs.validators {
                if jailed_raw.contains(&v.public_key_hex) || jailed_raw.contains(&v.node_id) {
                    out.insert(v.node_id.clone());
                }
            }
            out
        };

        // Wallet-Map: Alle bekannten Validatoren → public_key_hex als Wallet
        let mut wallet_map = HashMap::new();
        {
            let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
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
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            let idx = chain.blocks.len() as u64;
            let hash = chain.blocks.last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".into());
            (idx, hash)
        };
        // Schritt 2: Validator-Prüfung (chain NICHT gehalten)
        let should_sign = {
            let vs = self.validator_set.read().unwrap_or_else(|e| e.into_inner());
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
            let mut chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
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
                let mut ledger = self.token_ledger.write().unwrap_or_else(|e| e.into_inner());
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
                    if let Err(e) = store.write_block_sync(&block) {
                        eprintln!("[chain] ⚠️  RocksDB write_block_sync fehlgeschlagen: {e}");
                    }
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
            let mut vs_w = self.validator_set.write().unwrap_or_else(|e| e.into_inner());
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
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = peers.iter_mut().find(|p| p.url == peer.url) {
            *existing = peer;
        } else {
            peers.push(peer);
        }
    }

    /// Peer-Status aktualisieren
    pub fn set_peer_status(&self, url: &str, status: PeerStatus) {
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
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
        let mut locked = self.peers.write().unwrap_or_else(|e| e.into_inner());
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
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = peers.iter_mut().find(|p| p.url == url) {
            p.sync_failures = p.sync_failures.saturating_add(1);
        }
    }

    /// Peers lesen
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Staking-TXs aus einem Block im StakingPool verarbeiten + persistieren.
    /// Wird von allen Block-Ingestion-Pfaden aufgerufen (lokal, P2P, RangeSync).
    /// Nur TXs die im Ledger erfolgreich waren (receipt vorhanden) werden verarbeitet.
    pub fn apply_staking_from_txs(&self, txs: &[crate::token::TokenTx], receipts: &[crate::token::TxReceipt]) {
        use crate::token::TxType;
        let successful: std::collections::HashSet<&str> = receipts.iter().map(|r| r.tx_id.as_str()).collect();
        let mut pool = self.staking_pool.write().unwrap_or_else(|e| e.into_inner());
        let mut changed = false;
        for tx in txs {
            if !successful.contains(tx.tx_id.as_str()) {
                continue;
            }
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
                TxType::Delegate => {
                    // Default-Split: 70% Delegator / 30% Validator
                    let split_pct = 70u8;
                    if let Err(e) = pool.delegate(&tx.from, &tx.to, tx.amount, split_pct) {
                        eprintln!("[staking] Delegate fehlgeschlagen für {}: {e}", &tx.from[..12.min(tx.from.len())]);
                    } else {
                        changed = true;
                    }
                }
                TxType::Undelegate => {
                    if let Err(e) = pool.request_undelegate(&tx.from, &tx.to, tx.amount) {
                        eprintln!("[staking] Undelegate fehlgeschlagen für {}: {e}", &tx.from[..12.min(tx.from.len())]);
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

    /// Chain-Zusammenfassung für API-Antworten.
    ///
    /// Verwendet einen Cache der nur invalidiert wird wenn sich die Block-Höhe ändert.
    /// Vorher: O(n×m) list_all_documents() + calculate_hash() bei JEDEM Request.
    /// Jetzt: O(1) Cache-Hit, O(n×m) nur bei neuem Block (~alle 30s).
    pub fn chain_summary(&self) -> ChainSummary {
        // Schneller Cache-Hit ohne Chain-Lock
        {
            let cached = self.cached_summary.read().unwrap_or_else(|e| e.into_inner());
            if let Some(ref s) = *cached {
                let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
                if s.block_height == chain.blocks.len() as u64 {
                    return s.clone();
                }
            }
        }
        // Cache-Miss: Berechne neu
        let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
        let total_docs: usize = chain
            .list_all_documents()
            .len();
        let is_valid = if chain.blocks.len() >= 2 {
            let last = &chain.blocks[chain.blocks.len() - 1];
            let prev = &chain.blocks[chain.blocks.len() - 2];
            last.previous_hash == prev.hash
                && last.hash == crate::blockchain::calculate_hash(last)
        } else {
            true
        };
        let summary = ChainSummary {
            block_height: chain.blocks.len() as u64,
            latest_hash: chain.latest_hash.clone(),
            total_documents: total_docs as u64,
            is_valid,
        };
        drop(chain);
        // Cache aktualisieren
        if let Ok(mut w) = self.cached_summary.write() {
            *w = Some(summary.clone());
        }
        summary
    }

    /// Invalidiert den Chain-Summary-Cache.
    /// Muss nach jedem neuen Block aufgerufen werden.
    pub fn invalidate_summary_cache(&self) {
        if let Ok(mut w) = self.cached_summary.write() {
            *w = None;
        }
    }

    /// Aktualisiert die gecachten System-Ressourcen (RAM, CPU, Disk).
    /// Wird periodisch im Hintergrund aufgerufen (alle 10s) statt bei jedem Request.
    pub fn update_resource_cache(&self) {
        // Memory RSS
        let rss: u64 = {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/self/status")
                    .unwrap_or_default()
                    .lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0)
            }
            #[cfg(target_os = "macos")]
            {
                std::process::Command::new("ps")
                    .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            { 0 }
        };
        self.cached_memory_rss_kb.store(rss, Ordering::Relaxed);

        // CPU Time
        let cpu: u64 = {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/self/stat")
                    .unwrap_or_default()
                    .split_whitespace()
                    .enumerate()
                    .filter(|(i, _)| *i == 13 || *i == 14)
                    .map(|(_, v)| v.parse::<u64>().unwrap_or(0))
                    .sum::<u64>() * 10
            }
            #[cfg(not(target_os = "linux"))]
            { 0 }
        };
        self.cached_cpu_time_ms.store(cpu, Ordering::Relaxed);

        // Data dir size (rekursiv — teuer, aber nur alle 10s)
        fn dir_size(path: &std::path::Path) -> u64 {
            std::fs::read_dir(path)
                .map(|e| {
                    e.filter_map(|e| e.ok())
                        .map(|e| {
                            let meta = e.metadata().ok();
                            if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                                dir_size(&e.path())
                            } else {
                                meta.map(|m| m.len()).unwrap_or(0)
                            }
                        })
                        .sum()
                })
                .unwrap_or(0)
        }
        let bytes = dir_size(std::path::Path::new(&crate::blockchain::data_dir()));
        self.cached_data_dir_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Metriken für API
    pub fn snapshot_metrics(&self) -> MasterMetricsSnapshot {
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
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
}
