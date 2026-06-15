// ─── Gossip Block- & TX-Verarbeitung ──────────────────────────────────────────
//
// handle_gossip_block(): Validierung + Weiterleitung eingehender Blöcke
// handle_gossip_tx():    Validierung + Weiterleitung eingehender Transaktionen
//
// Beide Funktionen geben `gossipsub::MessageAcceptance` zurück. Der Dispatcher
// in `events.rs` ruft anschließend
// `gossipsub.report_message_validation_result(msg_id, source, acceptance)` auf:
//   - `Accept`  → Nachricht ans Mesh weiterleiten, Peer positiv scoren
//   - `Reject`  → NICHT weiterleiten + P4-Penalty (Mesh-Pruning)
//   - `Ignore`  → NICHT weiterleiten, kein Score-Effekt
//
// Wire-Format ist seit Protokoll v0.8 bincode (vorher JSON). Peers mit alter
// Version werden über den Major-Version-Check in `events.rs` / `sync.rs`
// getrennt, bevor sie überhaupt Block-Gossip bekommen.

use crate::blockchain::Block;
use crate::consensus::verify_block_signature_standalone;
use libp2p::{PeerId, gossipsub::MessageAcceptance};
use std::time::Instant;

use super::*;
use super::super::*;

impl SwarmTask {
    // ── Gossip Block verarbeiten ──────────────────────────────────────────────

    pub(super) fn handle_gossip_block(
        &mut self,
        data: Vec<u8>,
        source: PeerId,
    ) -> MessageAcceptance {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return MessageAcceptance::Ignore;
        }

        // ── Rate-Limit: Gossip-Blocks ─────────────────────────────────────────
        let limiter = self.peer_rate_limiters
            .entry(source)
            .or_insert_with(PeerRateLimiter::new);
        if !limiter.gossip_blocks.try_consume() {
            eprintln!("[p2p] ⚠ Rate-Limit für Gossip-Blocks von {source} erreicht – ignoriert");
            self.add_peer_penalty(&source, 15, "gossip block rate limit");
            return MessageAcceptance::Ignore;
        }

        // ── Größenlimit: Blöcke > 10 MiB sind verdächtig ──────────────────────
        const MAX_GOSSIP_BLOCK_BYTES: usize = 10 * 1024 * 1024;
        if data.len() > MAX_GOSSIP_BLOCK_BYTES {
            eprintln!(
                "[p2p] ⚠ Block von {source} zu groß ({} Bytes) – ignoriert + Penalty",
                data.len()
            );
            self.add_peer_penalty(&source, 50, "oversized block");
            return MessageAcceptance::Reject;
        }

        match super::decode_gossip::<Block>(&data) {
            Ok(block) => {
                // ── Duplicate-Filter ──────────────────────────────────────────
                if self.is_duplicate(&block.hash) {
                    return MessageAcceptance::Ignore;
                }

                // ── Hash-Integrität ───────────────────────────────────────────
                let expected_hash = crate::blockchain::calculate_hash(&block);
                if expected_hash != block.hash {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Hash – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid hash");
                    return MessageAcceptance::Reject;
                }

                // ── Merkle-Root-Verifikation ──────────────────────────────────
                let expected_merkle = crate::blockchain::compute_merkle_root(
                    &block.documents,
                    &block.tombstones,
                    &block.transactions,
                );
                if expected_merkle != block.merkle_root {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Merkle-Root – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid merkle root");
                    return MessageAcceptance::Reject;
                }

                // ── Timestamp-Drift-Check ─────────────────────────────────────
                // Block-Timestamp darf nicht > 5 Minuten in der Zukunft liegen
                // und nicht > 24 Stunden in der Vergangenheit (außer Genesis)
                let now = chrono::Utc::now().timestamp();
                let max_future = 5 * 60;       // 5 Minuten Toleranz
                let max_past = 24 * 60 * 60;   // 24 Stunden
                if block.index > 0 {
                    if block.timestamp > now + max_future {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} liegt {} Sek. in der Zukunft – ignoriert",
                            block.index,
                            block.timestamp - now,
                        );
                        self.add_peer_penalty(&source, 30, "future timestamp");
                        return MessageAcceptance::Reject;
                    }
                    if block.timestamp < now - max_past {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} ist {} Stunden alt – ignoriert",
                            block.index,
                            (now - block.timestamp) / 3600,
                        );
                        self.add_peer_penalty(&source, 10, "stale timestamp");
                        return MessageAcceptance::Reject;
                    }
                }

                // ── Signer darf nicht leer sein ───────────────────────────────
                if block.signer.is_empty() && block.index > 0 {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat keinen Signer – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 50, "missing signer");
                    return MessageAcceptance::Reject;
                }

                // ── Ed25519-Validator-Signatur prüfen ─────────────────────────
                if block.index > 0 {
                    if block.validator_pub_key.is_empty() || block.validator_signature.is_empty() {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} hat keine Validator-Signatur – ignoriert",
                            block.index
                        );
                        self.add_peer_penalty(&source, 100, "missing validator signature");
                        return MessageAcceptance::Reject;
                    }
                    if !verify_block_signature_standalone(
                        &block.hash,
                        &block.validator_pub_key,
                        &block.validator_signature,
                    ) {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} hat ungültige Validator-Signatur – ignoriert",
                            block.index
                        );
                        self.add_peer_penalty(&source, 200, "invalid validator signature");
                        return MessageAcceptance::Reject;
                    }
                }

                // ── Block-Größe vs. data_size Plausibilität ───────────────────
                let actual_data_size: u64 = block.documents.iter().map(|d| d.size).sum();
                if block.data_size > 0 && actual_data_size == 0 && !block.documents.is_empty() {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source}: data_size Mismatch – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 30, "data_size mismatch");
                    return MessageAcceptance::Reject;
                }

                // ── Argon2id-PoW Schnellprüfung (nur wenn BLOCK_POW_ENABLED) ─
                if crate::consensus::BLOCK_POW_ENABLED {
                    use crate::consensus::{
                        ARGON2_POW_ACTIVATION_BLOCK, MIN_EFFECTIVE_POW_DIFFICULTY,
                        MAX_STAKE_DIFFICULTY_BONUS,
                    };
                    if block.index >= ARGON2_POW_ACTIVATION_BLOCK && block.index > 0 {
                        if block.pow_hash.is_empty() || block.pow_difficulty == 0 {
                            eprintln!(
                                "[p2p] ⚠ Block #{} von {source}: Argon2id-PoW fehlt – ignoriert",
                                block.index
                            );
                            self.add_peer_penalty(&source, 100, "missing pow");
                            return MessageAcceptance::Reject;
                        }
                        // PoS/PoW Hybrid: effective_difficulty Plausibilität prüfen
                        if block.effective_difficulty > 0 {
                            if block.effective_difficulty > block.pow_difficulty {
                                eprintln!(
                                    "[p2p] ⚠ Block #{} von {source}: effective_difficulty ({}) > pow_difficulty ({}) – ignoriert",
                                    block.index, block.effective_difficulty, block.pow_difficulty,
                                );
                                self.add_peer_penalty(&source, 100, "invalid effective_difficulty");
                                return MessageAcceptance::Reject;
                            }
                            if block.effective_difficulty < MIN_EFFECTIVE_POW_DIFFICULTY {
                                eprintln!(
                                    "[p2p] ⚠ Block #{} von {source}: effective_difficulty ({}) < MIN ({}) – ignoriert",
                                    block.index, block.effective_difficulty, MIN_EFFECTIVE_POW_DIFFICULTY,
                                );
                                self.add_peer_penalty(&source, 100, "effective_difficulty below min");
                                return MessageAcceptance::Reject;
                            }
                            let bonus = block.pow_difficulty - block.effective_difficulty;
                            if bonus > MAX_STAKE_DIFFICULTY_BONUS {
                                eprintln!(
                                    "[p2p] ⚠ Block #{} von {source}: Stake-Bonus ({}) > MAX ({}) – ignoriert",
                                    block.index, bonus, MAX_STAKE_DIFFICULTY_BONUS,
                                );
                                self.add_peer_penalty(&source, 100, "stake bonus too high");
                                return MessageAcceptance::Reject;
                            }
                        }
                        // PoW gegen effektive Difficulty verifizieren
                        let verify_difficulty = if block.effective_difficulty > 0 {
                            block.effective_difficulty
                        } else {
                            block.pow_difficulty
                        };
                        if !crate::consensus::verify_argon2_pow(
                            &block.previous_hash,
                            block.index,
                            &block.validator_pub_key,
                            block.pow_nonce,
                            &block.pow_hash,
                            verify_difficulty,
                        ) {
                            eprintln!(
                                "[p2p] ⚠ Block #{} von {source}: Ungültiger Argon2id-PoW (d={}) – ignoriert",
                                block.index, verify_difficulty,
                            );
                            self.add_peer_penalty(&source, 200, "invalid argon2id pow");
                            return MessageAcceptance::Reject;
                        }
                    }
                }

                println!(
                    "[p2p] 📦 Block #{} von {source} (hash={}…, d={}/{}, cd={}) ✓ validiert",
                    block.index, &block.hash[..8],
                    block.effective_difficulty, block.pow_difficulty,
                    block.cumulative_difficulty,
                );

                if let Some(entry) = self.peers.get_mut(&source) {
                    entry.blocks_received += 1;
                    entry.last_seen = chrono::Utc::now().timestamp();
                }
                self.net_metrics.blocks_received += 1;

                // Aktuelle Chain-Höhe ohne Lock (über `local_chain_count`,
                // wird vom Master-Pfad via `SetLocalChainCount` aktualisiert).
                let actual_local = self.local_chain_count;

                if block.index < actual_local {
                    // ── Fork-Erkennung: Competing Block innerhalb Reorg-Tiefe ──
                    let depth = actual_local - block.index;
                    if depth <= crate::blockchain::MAX_REORG_DEPTH {
                        println!(
                            "[p2p] 🔀 Competing Block #{} von {source} (Tiefe: {depth}) – weiterleiten",
                            block.index,
                        );
                        let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                            block: Box::new(block),
                            from_peer: source.to_string(),
                        });
                        // Competing-Block ist gültig signiert → ans Mesh weiterreichen,
                        // damit andere Peers das Reorg-Voting sehen.
                        return MessageAcceptance::Accept;
                    }
                    // Blöcke jenseits MAX_REORG_DEPTH → wirklich veraltet,
                    // nicht weiterleiten aber kein Score-Penalty.
                    return MessageAcceptance::Ignore;
                }

                // Block ist voraus ODER Sync-Buffer ist aktiv → puffern
                if block.index > actual_local || !self.sync_buffer.is_empty() {
                    self.sync_buffer.insert(block.index, (block, source.to_string()));
                    self.sync_buffer_last_insert = Some(Instant::now());
                    self.flush_sync_buffer();
                } else {
                    // Normalfall: Block ist der nächste erwartete und kein Sync aktiv
                    let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                        block: Box::new(block),
                        from_peer: source.to_string(),
                    });
                }
                MessageAcceptance::Accept
            }
            Err(e) => {
                eprintln!("[p2p] Gossip Block-Dekodierung fehlgeschlagen von {source}: {e}");
                self.add_peer_penalty(&source, 20, "malformed block");
                MessageAcceptance::Reject
            }
        }
    }

    // ── Gossipsub: Token-TX empfangen ─────────────────────────────────────────

    pub(super) fn handle_gossip_tx(
        &mut self,
        data: Vec<u8>,
        source: PeerId,
    ) -> MessageAcceptance {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return MessageAcceptance::Ignore;
        }

        // ── Rate-Limit: Gossip-TXs ────────────────────────────────────────────
        let limiter = self.peer_rate_limiters
            .entry(source)
            .or_insert_with(PeerRateLimiter::new);
        if !limiter.gossip_txs.try_consume() {
            eprintln!("[p2p] ⚠ Rate-Limit für Gossip-TXs von {source} erreicht – ignoriert");
            self.add_peer_penalty(&source, 10, "gossip tx rate limit");
            return MessageAcceptance::Ignore;
        }

        // Größenlimit: TXs > 64 KiB sind verdächtig
        const MAX_TX_BYTES: usize = 64 * 1024;
        if data.len() > MAX_TX_BYTES {
            eprintln!(
                "[p2p] ⚠ TX von {source} zu groß ({} Bytes) – ignoriert",
                data.len()
            );
            self.add_peer_penalty(&source, 20, "oversized tx");
            return MessageAcceptance::Reject;
        }

        match super::decode_gossip::<crate::token::TokenTx>(&data) {
            Ok(tx) => {
                // Stake/Unstake-TXs dürfen nur lokal über authentifizierte
                // API-Handler erstellt werden – via P2P ablehnen.
                if tx.tx_type == crate::token::TxType::Stake
                    || tx.tx_type == crate::token::TxType::Unstake
                {
                    eprintln!(
                        "[p2p] ⚠ {:?}-TX {} von {source} via Gossip abgelehnt (nur lokal erlaubt)",
                        tx.tx_type, &tx.tx_id[..12.min(tx.tx_id.len())]
                    );
                    self.add_peer_penalty(&source, 50, "unauthorized stake/unstake via gossip");
                    return MessageAcceptance::Reject;
                }

                // Duplikat-Filter (tx_id basiert)
                let key = format!("tx:{}", tx.tx_id);
                if self.is_duplicate(&key) {
                    return MessageAcceptance::Ignore;
                }

                // Signatur prüfen
                if let Err(e) = crate::token::validate_tx(&tx) {
                    eprintln!(
                        "[p2p] ⚠ TX {} von {source} ungültige Signatur: {e} – ignoriert",
                        tx.tx_id
                    );
                    self.add_peer_penalty(&source, 30, "invalid tx signature");
                    return MessageAcceptance::Reject;
                }

                println!("[p2p] 💸 TX {} von {source} empfangen", &tx.tx_id[..12.min(tx.tx_id.len())]);

                self.net_metrics.txs_received += 1;

                let _ = self.event_tx.send(NetworkEvent::TxReceived {
                    tx: Box::new(tx),
                    from_peer: source.to_string(),
                });
                MessageAcceptance::Accept
            }
            Err(e) => {
                eprintln!("[p2p] Gossip TX-Dekodierung fehlgeschlagen von {source}: {e}");
                self.add_peer_penalty(&source, 10, "malformed tx");
                MessageAcceptance::Reject
            }
        }
    }
}
