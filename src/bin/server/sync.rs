//! Peer synchronisation logic: pull_from_peer, pull_users_from_peer,
//! fetch_missing_chunks, spawn_auto_sync_task.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use stone::{
    auth::{save_users, User},
    master_node::{MasterNodeState, NodeEvent, PeerStatus},
    storage::ChunkStore,
};

use super::state::AUTO_SYNC_INTERVAL;

/// Wandelt eine Peer-URL (z.B. http://1.2.3.4:8080) in die Sync-Port-URL um.
/// Der Sync-Port ist standardmäßig 4002, konfigurierbar via STONE_SYNC_PORT.
pub fn to_sync_url(peer_url: &str) -> String {
    let sync_port = std::env::var("STONE_SYNC_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(4002);

    let base = peer_url.trim_end_matches('/');
    // http://1.2.3.4:8080 → http://1.2.3.4:4002
    if let Some(pos) = base.rfind(':') {
        // Prüfen ob nach dem letzten : eine Portnummer steht
        let after = &base[pos + 1..];
        if after.parse::<u16>().is_ok() {
            return format!("{}:{}", &base[..pos], sync_port);
        }
    }
    // Kein Port in URL → einfach anhängen
    format!("{}:{}", base, sync_port)
}

pub async fn pull_from_peer(node: &Arc<MasterNodeState>, peer_url: &str, api_key: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[sync] HTTP-Client Fehler: {e}");
            node.set_peer_status(peer_url, PeerStatus::Unreachable);
            return;
        }
    };

    node.metrics.sync_runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let start = Instant::now();

    // Health-Check
    let health_url = format!("{}/api/v1/health", peer_url.trim_end_matches('/'));
    let health_resp = client.get(&health_url).send().await;
    let peer_height = match health_resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(val) = r.json::<serde_json::Value>().await {
                val.get("block_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            } else {
                0
            }
        }
        _ => {
            node.set_peer_status(peer_url, PeerStatus::Unreachable);
            node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
    };

    let local_height = {
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.blocks.len() as u64
    };

    if peer_height <= local_height {
        let latency = start.elapsed().as_millis();
        let local_hash = {
            let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.latest_hash.clone()
        };
        let mut peers = node.peers.write().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = peers.iter_mut().find(|p| p.url == peer_url) {
            p.mark_healthy(local_hash, local_height, latency);
        }
        node.metrics.sync_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }

    // ── Genesis-Check: Block #0 vom Peer holen und vergleichen ──
    {
        let gen_url = format!(
            "{}/api/v1/blocks/0",
            peer_url.trim_end_matches('/')
        );
        match client
            .get(&gen_url)
            .header("x-api-key", api_key)
            .header("x-node-request", "internal")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                if let Ok(peer_gen) = r.json::<stone::blockchain::Block>().await {
                    let local_gen_hash = {
                        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                        chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default()
                    };
                    if !local_gen_hash.is_empty() && local_gen_hash != peer_gen.hash {
                        eprintln!("[sync] {peer_url}: Genesis-Mismatch – inkompatibler Peer \
                                   (lokal={}, peer={})",
                                  &local_gen_hash[..12.min(local_gen_hash.len())],
                                  &peer_gen.hash[..12.min(peer_gen.hash.len())]);
                        node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }
            }
            _ => {
                eprintln!("[sync] {peer_url}: Genesis-Block nicht abrufbar – überspringe");
                node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        }
    }

    // ── Blöcke seitenweise abrufen (ab local_height aufsteigend) ──
    // Die API liefert Blöcke absteigend (.rev()), daher berechnen wir die
    // richtige Seite, um alle Blöcke ab local_height zu bekommen.
    let per_page: u64 = 500;
    let mut all_blocks: Vec<stone::blockchain::Block> = Vec::new();

    // Wir brauchen Blöcke von local_height bis peer_height.
    // Die API paginiert absteigend: page 0 = neueste per_page Blöcke.
    // Statt die API umzubauen, holen wir alle Seiten die unseren Bereich abdecken.
    let total_pages = (peer_height + per_page - 1) / per_page;
    'page_loop: for page in 0..total_pages {
        let blocks_url = format!(
            "{}/api/v1/blocks?per_page={}&page={}",
            peer_url.trim_end_matches('/'),
            per_page,
            page
        );
        let resp = match client
            .get(&blocks_url)
            .header("x-api-key", api_key)
            .header("x-node-request", "internal")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[sync] {peer_url} blocks request (page {page}): {e}");
                node.set_peer_status(peer_url, PeerStatus::Unreachable);
                node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };

        let val: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[sync] {peer_url} parse error (page {page}): {e}");
                node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };

        let page_blocks: Vec<stone::blockchain::Block> = match val
            .get("blocks")
            .and_then(|b| serde_json::from_value(b.clone()).ok())
        {
            Some(b) => b,
            None => {
                eprintln!("[sync] {peer_url}: Kein 'blocks' Feld (page {page})");
                break;
            }
        };

        if page_blocks.is_empty() {
            break;
        }

        // Prüfen ob wir bereits alle benötigten Blöcke haben
        let has_needed = page_blocks.iter().any(|b| b.index >= local_height);
        all_blocks.extend(page_blocks);

        if has_needed {
            // Diese Seite enthält Blöcke ab local_height – eventuell brauchen
            // wir noch ältere Seiten für den Bereich dazwischen.
            // Prüfe ob wir alles ab local_height lückenlos haben:
            all_blocks.sort_by_key(|b| b.index);
            let min_idx = all_blocks.first().map(|b| b.index).unwrap_or(0);
            if min_idx <= local_height {
                break 'page_loop; // Wir haben alles ab local_height
            }
        }
    }

    // Aufsteigend nach Index sortieren + deduplizieren
    all_blocks.sort_by_key(|b| b.index);
    all_blocks.dedup_by_key(|b| b.index);
    let blocks = all_blocks;

    let mut added = 0u64;

    // Hash-Integrität aller Peer-Blöcke prüfen
    let blocks: Vec<_> = blocks
        .into_iter()
        .filter(|b| stone::blockchain::calculate_hash(b) == b.hash)
        .collect();

    // Fork-Erkennung + Rollback
    let (pending_blocks, did_rollback) = {
        let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let local_len = chain.blocks.len() as u64;

        let mut fork_at: Option<usize> = None;
        for peer_block in &blocks {
            let idx = peer_block.index as usize;
            if idx < chain.blocks.len() && chain.blocks[idx].hash != peer_block.hash {
                fork_at = Some(idx);
                break;
            }
        }

        let did_rollback = if let Some(fork_idx) = fork_at {
            let peer_len = blocks.len() as u64;

            // ── Stake-gewichtete Fork-Choice ──
            // Nicht nur Länge vergleichen, sondern auch kumulatives Stake-Gewicht
            let (stakes, _jailed, wallet_map) = node.build_selection_context();
            let local_stake = stone::consensus::cumulative_stake_weight(
                &chain.blocks, fork_idx, &stakes, &wallet_map,
            );
            let peer_stake = stone::consensus::cumulative_stake_weight(
                &blocks, fork_idx, &stakes, &wallet_map,
            );

            let (prefer_peer, reason) = stone::consensus::should_prefer_peer_chain(
                local_len, peer_len, local_stake, peer_stake,
            );

            if prefer_peer {
                // ── Checkpoint-Schutz: Reorg über finalisierte Checkpoints verhindern ──
                {
                    let cp_store = node.checkpoint_store.read().unwrap_or_else(|e| e.into_inner());
                    if let Err(cp_reason) = cp_store.check_reorg_allowed(fork_idx as u64) {
                        eprintln!(
                            "[sync] {peer_url}: Fork bei Index {fork_idx} ABGELEHNT – {cp_reason}"
                        );
                        node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }

                eprintln!(
                    "[sync] {peer_url}: Fork bei Index {fork_idx} erkannt – {reason} \
                     (Peer: {peer_len} Blöcke/{peer_stake} Stake, Lokal: {local_len}/{local_stake}) → Rollback"
                );
                chain.blocks.truncate(fork_idx);
                chain.latest_hash = chain
                    .blocks
                    .last()
                    .map(|b| b.hash.clone())
                    .unwrap_or_default();
                chain.persist_all();
                true
            } else {
                eprintln!(
                    "[sync] {peer_url}: Fork bei Index {fork_idx} – {reason} \
                     (Peer: {peer_len}/{peer_stake}, Lokal: {local_len}/{local_stake}) → behalte lokale Chain"
                );
                false
            }
        } else {
            false
        };

        let cur_len = chain.blocks.len() as u64;
        let pending: Vec<stone::blockchain::Block> =
            blocks.into_iter().filter(|b| b.index >= cur_len).collect();

        (pending, did_rollback)
    };

    if did_rollback {
        eprintln!(
            "[sync] {peer_url}: Rollback abgeschlossen, übernehme {} neue Blöcke",
            pending_blocks.len()
        );
    }

    // Chunks laden
    let chunk_store = ChunkStore::new().unwrap_or_default();
    for block in &pending_blocks {
        for doc in &block.documents {
            for ch in &doc.chunks {
                if chunk_store.has_chunk(&ch.hash) {
                    continue;
                }
                let chunk_url = format!(
                    "{}/api/v1/chunk/{}",
                    peer_url.trim_end_matches('/'),
                    ch.hash
                );
                match client
                    .get(&chunk_url)
                    .header("x-api-key", api_key)
                    .header("x-node-request", "internal")
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(bytes) = r.bytes().await {
                            let _ = chunk_store.write_chunk(&bytes);
                            println!("[sync] ✓ Chunk {} von {peer_url} geholt", &ch.hash[..8]);
                        }
                    }
                    Ok(r) => eprintln!("[sync] Chunk {} – HTTP {}", &ch.hash[..8], r.status()),
                    Err(e) => eprintln!("[sync] Chunk {} – Fehler: {e}", &ch.hash[..8]),
                }
            }
        }
    }

    // Blöcke in Chain eintragen + Token-TXs verarbeiten (mit Validierung)
    {
        let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        for block in pending_blocks {
            let idx = block.index;
            let block_txs = block.transactions.clone();

            // accept_peer_block: Hash, Merkle, Memorial, Storage-Proof, Timestamp etc.
            // poa_ok = None → kein PoA-Check (HTTP-Sync hat keinen Validator-Set-Kontext)
            match chain.accept_peer_block(block, None) {
                Ok(_) => {
                    // Token-TXs im Ledger verarbeiten
                    if !block_txs.is_empty() {
                        let mut ledger = node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                        let receipts = ledger.apply_block_txs(&block_txs, idx);
                        if !receipts.is_empty() {
                            if let Err(e) = ledger.persist() {
                                eprintln!("[token] Ledger-Persist nach Sync-Block #{idx}: {e}");
                            }
                        }
                        // TXs aus eigenem Mempool entfernen
                        for tx in &block_txs {
                            node.mempool.mark_known(&tx.tx_id);
                            node.mempool.remove_tx(&tx.tx_id);
                        }
                    }

                    added += 1;
                }
                Err(ref e) if e.starts_with("Stale:") => {
                    // Block bereits bekannt – stillschweigend ignorieren
                }
                Err(e) => {
                    eprintln!("[sync] {peer_url}: Block #{idx} abgelehnt: {e}");
                    break; // Bei Validierungsfehler abbrechen
                }
            }
        }
    }

    if added > 0 {
        node.events.publish(NodeEvent::SyncCompleted {
            peer_url: peer_url.to_string(),
            blocks_added: added,
        });
        eprintln!("[sync] {peer_url}: {} Blöcke hinzugefügt", added);
    }

    let latency = start.elapsed().as_millis();
    let latest_hash = {
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.latest_hash.clone()
    };
    let mut peers = node.peers.write().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = peers.iter_mut().find(|p| p.url == peer_url) {
        p.mark_healthy(latest_hash, local_height + added, latency);
    }
    node.metrics.sync_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Holt fehlende Chunks für einen empfangenen Peer-Block via HTTP.
pub async fn fetch_missing_chunks(
    block: &stone::blockchain::Block,
    peer_base_url: &str,
    _api_key: &str,
) {
    let chunk_store = match ChunkStore::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[sync] ChunkStore nicht verfügbar: {e}");
            return;
        }
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    for doc in &block.documents {
        for chunk_ref in &doc.chunks {
            if chunk_store.read_chunk(&chunk_ref.hash).is_ok() {
                continue;
            }
            let url = format!(
                "{}/api/v1/chunk/{}",
                peer_base_url.trim_end_matches('/'),
                chunk_ref.hash
            );
            match client
                .get(&url)
                .header("x-node-request", "internal")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(bytes) => {
                            match chunk_store.write_chunk(&bytes) {
                                Ok(written_hash) if written_hash == chunk_ref.hash => {
                                    println!(
                                        "[sync] ✓ Chunk {} von {peer_base_url} geholt",
                                        &chunk_ref.hash[..8]
                                    );
                                }
                                Ok(written_hash) => {
                                    eprintln!(
                                        "[sync] Chunk-Hash-Mismatch: erwartet {}, bekommen {}",
                                        &chunk_ref.hash[..8],
                                        &written_hash[..8]
                                    );
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[sync] Chunk {} speichern fehlgeschlagen: {e}",
                                        &chunk_ref.hash[..8]
                                    );
                                }
                            }
                        }
                        Err(e) => eprintln!(
                            "[sync] Chunk {} lesen fehlgeschlagen: {e}",
                            &chunk_ref.hash[..8]
                        ),
                    }
                }
                Ok(resp) => {
                    eprintln!(
                        "[sync] Chunk {} – HTTP {}",
                        &chunk_ref.hash[..8],
                        resp.status()
                    );
                }
                Err(e) => {
                    eprintln!("[sync] Chunk {} – Fehler: {e}", &chunk_ref.hash[..8]);
                }
            }
        }
    }
}

pub fn spawn_auto_sync_task(
    node: Arc<MasterNodeState>,
    api_key: Arc<String>,
    users: Arc<Mutex<Vec<User>>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AUTO_SYNC_INTERVAL);
        let mut chain_sync_counter: u64 = 0;
        loop {
            interval.tick().await;
            let peers = node.get_peers();
            for peer in &peers {
                pull_from_peer(&node, &peer.url, &api_key).await;
                pull_users_from_peer(&peer.url, &api_key, &users).await;
            }
            // Push eigene User an alle erreichbaren Peers (wichtig wenn wir
            // hinter NAT sind und Peers uns nicht pullen können)
            push_all_users_to_peers(&peers.iter().map(|p| p.url.clone()).collect::<Vec<_>>(), &users).await;
            // Alle 2 Minuten: Chain-registrierte Accounts in lokale User-Liste mergen
            chain_sync_counter += 1;
            if chain_sync_counter % 4 == 0 {
                sync_chain_accounts_to_users(&node, &users);
            }
        }
    });
}

/// Pusht die gesamte lokale User-Liste an alle erreichbaren Peers via Sync-Port.
/// Damit funktioniert die Sync auch wenn der Peer uns nicht erreichen kann (NAT).
pub async fn push_all_users_to_peers(
    peer_urls: &[String],
    users: &Arc<Mutex<Vec<User>>>,
) {
    let user_list: Vec<serde_json::Value> = {
        let local = users.lock().unwrap_or_else(|e| e.into_inner());
        local
            .iter()
            .filter(|u| !u.name.is_empty())
            .map(|u| {
                serde_json::json!({
                    "id": u.id,
                    "name": u.name,
                    "wallet_address": u.wallet_address,
                })
            })
            .collect()
    };

    if user_list.is_empty() {
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    for peer_url in peer_urls {
        let sync_url = to_sync_url(peer_url);
        let url = format!("{}/sync-users", sync_url);
        match client.post(&url).json(&user_list).send().await {
            Ok(r) if r.status().is_success() => {
                // Leise — wird alle 30s aufgerufen
            }
            Ok(_) | Err(_) => {
                // Peer nicht erreichbar — überspringen
            }
        }
    }
}

/// Holt die Nutzerliste von einem Peer via Sync-Port (kein Auth nötig).
pub async fn pull_users_from_peer(
    peer_url: &str,
    _api_key: &str,
    users: &Arc<Mutex<Vec<User>>>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/users", sync_url);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return, // Peer nicht erreichbar — leise überspringen
    };

    if !resp.status().is_success() {
        return;
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return,
    };

    let remote_users_raw = match body.get("users").and_then(|u| u.as_array()) {
        Some(arr) => arr,
        None => return,
    };

    let mut local = users.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;
    let mut updated = 0usize;

    for ru in remote_users_raw {
        let id = ru["id"].as_str().unwrap_or_default().to_string();
        let name = ru["name"].as_str().unwrap_or_default().to_string();
        let wallet = ru["wallet_address"].as_str().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        // Match by wallet (bevorzugt) oder ID
        let existing = local.iter_mut().find(|u| {
            (!u.wallet_address.is_empty() && !wallet.is_empty() && u.wallet_address == wallet)
                || (!id.is_empty() && u.id == id)
        });
        if let Some(ex) = existing {
            if ex.name != name {
                ex.name = name;
                updated += 1;
            }
            if ex.wallet_address.is_empty() && !wallet.is_empty() {
                ex.wallet_address = wallet;
                updated += 1;
            }
            continue;
        }
        // Neuer User — minimalen Eintrag anlegen
        local.push(User {
            id: if id.is_empty() {
                format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"))
            } else {
                id
            },
            name,
            api_key: String::new(),
            phrase_hash: String::new(),
            quota_bytes: stone::auth::default_quota_bytes(),
            wallet_address: wallet,
            account_type: stone::auth::default_account_type(),
            org_id: String::new(),
            org_role: String::new(),
        });
        added += 1;
    }

    if added > 0 || updated > 0 {
        save_users(&local);
        println!("[sync] {added} neue + {updated} aktualisierte Nutzer von {peer_url}");
    }
}

/// Synchronisiert on-chain registrierte Accounts in die lokale User-Liste.
///
/// Wird periodisch aufgerufen um sicherzustellen, dass Accounts die via
/// AccountRegister-TX auf anderen Nodes registriert wurden, auch lokal
/// auffindbar sind (wichtig für Chat-Resolve und User-Suche).
pub fn sync_chain_accounts_to_users(
    node: &Arc<MasterNodeState>,
    users: &Arc<Mutex<Vec<User>>>,
) {
    let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let chain_accounts = ledger.all_registered_accounts();
    if chain_accounts.is_empty() {
        return;
    }

    let mut local = users.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;

    for (wallet, name) in chain_accounts {
        // Bereits vorhanden (über Wallet ODER Name+ApiKey)?
        let exists = local.iter().any(|u| {
            u.wallet_address == *wallet
            || (!u.api_key.is_empty()
                && ledger.account_api_key_hash(wallet).map_or(false, |h| h == u.api_key))
        });
        if exists {
            // Wallet-Adresse nachrüsten falls leer
            if let Some(u) = local.iter_mut().find(|u| {
                u.wallet_address.is_empty()
                    && !u.api_key.is_empty()
                    && ledger.account_api_key_hash(wallet).map_or(false, |h| h == u.api_key)
            }) {
                u.wallet_address = wallet.clone();
                added += 1; // Zählt als Update
            }
            continue;
        }
        // Neuen User-Eintrag anlegen
        let api_key_hash = ledger.account_api_key_hash(wallet)
            .unwrap_or_default().to_string();
        let id = format!("u-{}", uuid::Uuid::new_v4().to_string()
            .split('-').next().unwrap_or("0000"));

        local.push(User {
            id,
            name: name.clone(),
            api_key: api_key_hash.clone(),
            phrase_hash: api_key_hash,
            quota_bytes: stone::auth::default_quota_bytes(),
            wallet_address: wallet.clone(),
            account_type: stone::auth::default_account_type(),
            org_id: String::new(),
            org_role: String::new(),
        });
        added += 1;
    }

    if added > 0 {
        save_users(&local);
        println!("[sync] 📋 {added} Chain-Accounts in lokale User-Liste synchronisiert");
    }
}
