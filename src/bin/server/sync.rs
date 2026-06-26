//! Peer synchronisation logic: pull_from_peer, pull_users_from_peer,
//! pull_game_economy_from_peer, pull_organizations_from_peer, spawn_auto_sync_task.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use stone::{
    auth::{save_users, User},
    chat::ChatIndex,
    consensus::verify_block_signature_standalone,
    database::DbMetadata,
    master::{MasterNodeState, NodeEvent, PeerStatus, PeerInfo, TrustEntry, TrustVote},
    message_pool::PooledMessage,
    organization::{load_orgs, save_orgs, Organization},
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
    if let Some(pos) = base.rfind(':') {
        let after = &base[pos + 1..];
        if after.parse::<u16>().is_ok() {
            return format!("{}:{}", &base[..pos], sync_port);
        }
    }
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

    node.metrics.syncing_from_height.store(local_height, std::sync::atomic::Ordering::Relaxed);
    node.metrics.syncing_to_height.store(peer_height, std::sync::atomic::Ordering::Relaxed);

    // Genesis-Check
    {
        let gen_url = format!("{}/api/v1/blocks/0", peer_url.trim_end_matches('/'));
        match client.get(&gen_url).header("x-api-key", api_key).header("x-node-request", "internal").send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(peer_gen) = r.json::<stone::blockchain::Block>().await {
                    let local_gen_hash = {
                        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
                        chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default()
                    };
                    if !local_gen_hash.is_empty() && local_gen_hash != peer_gen.hash {
                        eprintln!("[sync] {peer_url}: Genesis-Mismatch – inkompatibler Peer");
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

    // Blöcke abrufen
    let per_page: u64 = 500;
    let mut all_blocks: Vec<stone::blockchain::Block> = Vec::new();
    let total_pages = (peer_height + per_page - 1) / per_page;
    'page_loop: for page in 0..total_pages {
        let blocks_url = format!("{}/api/v1/blocks?per_page={}&page={}&detail=true", peer_url.trim_end_matches('/'), per_page, page);
        let resp = match client.get(&blocks_url).header("x-api-key", api_key).header("x-node-request", "internal").send().await {
            Ok(r) => r,
            Err(e) => { eprintln!("[sync] {peer_url} blocks request (page {page}): {e}"); node.set_peer_status(peer_url, PeerStatus::Unreachable); node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed); return; }
        };
        let val: serde_json::Value = match resp.json().await { Ok(v) => v, Err(e) => { eprintln!("[sync] {peer_url} parse error (page {page}): {e}"); node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed); return; } };
        let page_blocks: Vec<stone::blockchain::Block> = match val.get("blocks").and_then(|b| serde_json::from_value(b.clone()).ok()) { Some(b) => b, None => break };
        if page_blocks.is_empty() { break; }
        let has_needed = page_blocks.iter().any(|b| b.index >= local_height);
        all_blocks.extend(page_blocks);
        if has_needed {
            all_blocks.sort_by_key(|b| b.index);
            let min_idx = all_blocks.first().map(|b| b.index).unwrap_or(0);
            if min_idx <= local_height { break 'page_loop; }
        }
    }

    all_blocks.sort_by_key(|b| b.index);
    all_blocks.dedup_by_key(|b| b.index);
    let blocks: Vec<_> = all_blocks.into_iter().filter(|b| stone::blockchain::calculate_hash(b) == b.hash).collect();

    let mut added = 0u64;
    let (pending_blocks, did_rollback) = {
        let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let local_len = chain.blocks.len() as u64;
        let mut fork_at: Option<usize> = None;
        for peer_block in &blocks {
            let idx = peer_block.index as usize;
            if idx < chain.blocks.len() && chain.blocks[idx].hash != peer_block.hash { fork_at = Some(idx); break; }
        }
        let did_rollback = if let Some(fork_idx) = fork_at {
            let peer_len = blocks.iter().map(|b| b.index.saturating_add(1)).max().unwrap_or(peer_height);
            let (stakes, _jailed, wallet_map) = node.build_selection_context();
            let local_stake = stone::consensus::cumulative_stake_weight(&chain.blocks, fork_idx, &stakes, &wallet_map);
            let peer_offset = blocks.iter().position(|b| b.index as usize >= fork_idx).unwrap_or(blocks.len());
            let peer_stake = stone::consensus::cumulative_stake_weight(&blocks, peer_offset, &stakes, &wallet_map);
            let local_fork_hash = chain.blocks.get(fork_idx).map(|b| b.hash.as_str()).unwrap_or("");
            let peer_fork_hash = blocks.iter().find(|b| b.index as usize == fork_idx).map(|b| b.hash.as_str()).unwrap_or("");
            let (prefer_peer, reason) = stone::consensus::should_prefer_peer_chain_with_hashes(local_len, peer_len, local_stake, peer_stake, local_fork_hash, peer_fork_hash);
            if prefer_peer {
                let cp_store = node.checkpoint_store.read().unwrap_or_else(|e| e.into_inner());
                if let Err(cp_reason) = cp_store.check_reorg_allowed(fork_idx as u64) {
                    eprintln!("[sync] {peer_url}: Fork bei Index {fork_idx} ABGELEHNT – {cp_reason}");
                    node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                eprintln!("[sync] {peer_url}: Fork bei Index {fork_idx} erkannt – {reason} → Rollback");
                chain.blocks.truncate(fork_idx);
                chain.latest_hash = chain.blocks.last().map(|b| b.hash.clone()).unwrap_or_default();
                chain.persist_all();
                true
            } else {
                eprintln!("[sync] {peer_url}: Fork bei Index {fork_idx} – {reason} → behalte lokale Chain");
                false
            }
        } else { false };
        let cur_len = chain.blocks.len() as u64;
        let pending: Vec<stone::blockchain::Block> = blocks.into_iter().filter(|b| b.index >= cur_len).collect();
        (pending, did_rollback)
    };

    if did_rollback {
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        let rebuilt = stone::token::TokenLedger::rebuild_from_chain(&chain.blocks);
        let mut ledger = node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
        *ledger = rebuilt;
        eprintln!("[sync] Token-Ledger nach Rollback neu aufgebaut: {} Accounts", ledger.account_count());
    }

    // Blöcke in Chain + Token-TXs verarbeiten
    {
        let mut chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        for block in pending_blocks {
            let idx = block.index;
            let block_txs = block.transactions.clone();
            match chain.accept_peer_block(block, Some(true), Some(&*node.checkpoint_store.read().unwrap_or_else(|e| e.into_inner()))) {
                Ok(_) => {
                    if !block_txs.is_empty() {
                        let mut ledger = node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                        ledger.replay_mode = true;
                        let _ = ledger.apply_block_txs(&block_txs, idx);
                        ledger.replay_mode = false;
                        let _ = ledger.persist();
                        for tx in &block_txs { node.mempool.mark_known(&tx.tx_id); node.mempool.remove_tx(&tx.tx_id); }
                    }
                    added += 1;
                }
                Err(ref e) if e.starts_with("Stale:") => {}
                Err(e) => { eprintln!("[sync] {peer_url}: Block #{idx} abgelehnt: {e}"); break; }
            }
        }
    }

    if added > 0 {
        node.events.publish(NodeEvent::SyncCompleted { peer_url: peer_url.to_string(), blocks_added: added });
        eprintln!("[sync] {peer_url}: {} Blöcke hinzugefügt", added);
    }

    if !node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed) {
        node.metrics.initial_sync_done.store(true, std::sync::atomic::Ordering::Relaxed);
        eprintln!("[sync] ✅ Initial-Sync abgeschlossen nach Sync mit {peer_url}");
        let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner());
        if chain.blocks.len() > 1 {
            let rebuilt = stone::token::TokenLedger::rebuild_from_chain(&chain.blocks);
            let mut ledger = node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
            *ledger = rebuilt;
            eprintln!("[token] 🔄 Ledger nach Initial-Sync rebuilt: {} Accounts", ledger.account_count());
        }
    }

    let latency = start.elapsed().as_millis();
    let latest_hash = { let chain = node.chain.lock().unwrap_or_else(|e| e.into_inner()); chain.latest_hash.clone() };
    let mut peers = node.peers.write().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = peers.iter_mut().find(|p| p.url == peer_url) {
        p.mark_healthy(latest_hash, local_height + added, latency);
    }
    node.metrics.syncing_to_height.store(0, std::sync::atomic::Ordering::Relaxed);
    node.metrics.sync_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Holt den Game-Economy-Store von einem Peer und mergt ihn in den lokalen.
pub async fn pull_game_economy_from_peer(node: &Arc<MasterNodeState>, peer_url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/game-economy", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let economy_json = match body.get("game_economy") { Some(v) => v.clone(), None => return };

    let mut local = node.game_economy.write().unwrap_or_else(|e| e.into_inner());

    if let Some(remote_games) = economy_json.get("registered_games").and_then(|v| v.as_object()) {
        for (game_id, game_val) in remote_games {
            if !local.registered_games.contains_key(game_id) {
                if let Ok(game) = serde_json::from_value(game_val.clone()) {
                    local.registered_games.insert(game_id.clone(), game);
                }
            }
        }
    }

    if let Some(remote_shop) = economy_json.get("shop_items").and_then(|v| v.as_object()) {
        for (item_id, item_val) in remote_shop {
            if !local.shop_items.contains_key(item_id) {
                if let Ok(item) = serde_json::from_value(item_val.clone()) {
                    local.shop_items.insert(item_id.clone(), item);
                }
            }
        }
    }

    let games_added = local.registered_games.len();
    let shop_added = local.shop_items.len();
    println!("[sync] 🎮 Game-Economy Sync von {peer_url}: {} Games, {} Shop-Items", games_added, shop_added);

    if let Err(e) = local.persist() {
        eprintln!("[sync] ⚠️ Game-Economy Persistierung fehlgeschlagen: {e}");
    }
}

/// Holt die Organisations-Liste von einem Peer und merged sie lokal.
pub async fn pull_organizations_from_peer(orgs: &Arc<Mutex<Vec<Organization>>>, peer_url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/organizations", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let sync_list = match body.get("organizations") { Some(s) => s.clone(), None => return };
    let entries: Vec<stone::organization::OrgSyncEntry> =
        match serde_json::from_value(sync_list.clone()) {
            Ok(e) => e,
            Err(_) => {
                // Versuche als OrgSyncList wrapper
                if let Ok(wrapped) =
                    serde_json::from_value::<stone::organization::OrgSyncList>(sync_list)
                {
                    wrapped.organizations
                } else {
                    return;
                }
            }
        };

    let mut local = orgs.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;
    let mut updated = 0usize;

    for inc in &entries {
        if inc.chain_hash.is_empty() {
            continue;
        }
        // Verifiziere Proof-Hash
        let reconstructed = {
            let mut h = sha2::Sha256::new();
            use sha2::Digest;
            h.update(inc.id.as_bytes());
            h.update(inc.name.as_bytes());
            h.update(inc.owner_id.as_bytes());
            h.update(&inc.created_at.to_le_bytes());
            hex::encode(h.finalize())
        };
        if reconstructed != inc.chain_hash {
            continue;
        }

        if let Some(existing) = local.iter_mut().find(|o| o.id == inc.id) {
            if existing.chain_block_index < inc.chain_block_index {
                existing.chain_hash = inc.chain_hash.clone();
                existing.chain_block_index = inc.chain_block_index;
                existing.chain_block_hash = inc.chain_block_hash.clone();
                updated += 1;
            }
        } else {
            let mut org = Organization::create(&inc.name, &inc.description, &inc.owner_id, "synced-user");
            org.id = inc.id.clone();
            org.chain_hash = inc.chain_hash.clone();
            org.chain_block_index = inc.chain_block_index;
            org.chain_block_hash = inc.chain_block_hash.clone();
            org.created_at = inc.created_at;
            local.push(org);
            added += 1;
        }
    }

    if added > 0 || updated > 0 {
        save_orgs(&local);
        println!("[sync] 🏢 {added} neue + {updated} aktualisierte Organisationen von {peer_url}");
    }
}

/// Pusht die lokalen Orgs zu allen Peers.
pub async fn push_all_orgs_to_peers(peer_urls: &[String], orgs: &Arc<Mutex<Vec<Organization>>>) {
    let org_sync = {
        let local = orgs.lock().unwrap_or_else(|e| e.into_inner());
        stone::organization::build_org_sync_list(&local)
    };
    if org_sync.organizations.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    for peer_url in peer_urls {
        let sync_url = to_sync_url(peer_url);
        let url = format!("{}/sync-organizations", sync_url);
        let _ = client.post(&url).json(&org_sync).send().await;
    }
}

pub fn spawn_auto_sync_task(
    node: Arc<MasterNodeState>,
    api_key: Arc<String>,
    users: Arc<Mutex<Vec<User>>>,
    orgs: Arc<Mutex<Vec<Organization>>>,
    chat_idx: Arc<std::sync::Mutex<ChatIndex>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AUTO_SYNC_INTERVAL);
        let mut chain_sync_counter: u64 = 0;
        loop {
            interval.tick().await;
            let mut peers = node.get_peers();
            peers.sort_by(|a, b| b.block_height.cmp(&a.block_height));
            let initial_done = node.metrics.initial_sync_done.load(std::sync::atomic::Ordering::Relaxed);

            if !initial_done {
                if let Some(best) = peers.first() {
                    pull_from_peer(&node, &best.url, &api_key).await;
                    pull_db_from_peer(&node, &best.url).await;
                    pull_users_from_peer(&best.url, &api_key, &users).await;
                    pull_game_economy_from_peer(&node, &best.url).await;
                    pull_organizations_from_peer(&orgs, &best.url).await;
                    pull_message_pool_from_peer(&node, &best.url, &chat_idx).await;
                } else {
                    node.metrics.initial_sync_done.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            } else {
                for peer in &peers {
                    pull_from_peer(&node, &peer.url, &api_key).await;
                    pull_db_from_peer(&node, &peer.url).await;
                    pull_users_from_peer(&peer.url, &api_key, &users).await;
                    pull_game_economy_from_peer(&node, &peer.url).await;
                    pull_organizations_from_peer(&orgs, &peer.url).await;
                    pull_message_pool_from_peer(&node, &peer.url, &chat_idx).await;
                }
            }

            push_all_users_to_peers(&peers.iter().map(|p| p.url.clone()).collect::<Vec<_>>(), &users).await;
            push_all_orgs_to_peers(&peers.iter().map(|p| p.url.clone()).collect::<Vec<_>>(), &orgs).await;
            chain_sync_counter += 1;
            if chain_sync_counter % 4 == 0 {
                sync_chain_accounts_to_users(&node, &users);
            }
        }
    });
}

pub async fn push_all_users_to_peers(
    peer_urls: &[String],
    users: &Arc<Mutex<Vec<User>>>,
) {
    let user_list: Vec<serde_json::Value> = {
        let local = users.lock().unwrap_or_else(|e| e.into_inner());
        local.iter().filter(|u| !u.name.is_empty()).map(|u| {
            serde_json::json!({ "id": u.id, "name": u.name, "wallet_address": u.wallet_address, "api_key": u.api_key, "phrase_hash": u.phrase_hash })
        }).collect()
    };
    if user_list.is_empty() { return; }
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false)).build() { Ok(c) => c, Err(_) => return };
    for peer_url in peer_urls {
        let sync_url = to_sync_url(peer_url);
        let url = format!("{}/sync-users", sync_url);
        let _ = client.post(&url).json(&user_list).send().await;
    }
}

pub async fn pull_users_from_peer(peer_url: &str, _api_key: &str, users: &Arc<Mutex<Vec<User>>>) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false)).build() { Ok(c) => c, Err(_) => return };
    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/users", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let remote_users_raw = match body.get("users").and_then(|u| u.as_array()) { Some(arr) => arr, None => return };

    let mut local = users.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;
    let mut updated = 0usize;
    for ru in remote_users_raw {
        let id = ru["id"].as_str().unwrap_or_default().to_string();
        let name = ru["name"].as_str().unwrap_or_default().to_string();
        let wallet = ru["wallet_address"].as_str().unwrap_or_default().to_string();
        let api_key = ru["api_key"].as_str().unwrap_or_default().to_string();
        let phrase_hash = ru["phrase_hash"].as_str().unwrap_or_default().to_string();
        if name.is_empty() { continue; }
        let existing = local.iter_mut().find(|u| {
            (!u.wallet_address.is_empty() && !wallet.is_empty() && u.wallet_address == wallet) || (!id.is_empty() && u.id == id)
        });
        if let Some(ex) = existing {
            if ex.name != name { ex.name = name; updated += 1; }
            if ex.wallet_address.is_empty() && !wallet.is_empty() { ex.wallet_address = wallet; updated += 1; }
            if ex.api_key.is_empty() && !api_key.is_empty() { ex.api_key = api_key; updated += 1; }
            if ex.phrase_hash.is_empty() && !phrase_hash.is_empty() { ex.phrase_hash = phrase_hash; updated += 1; }
            continue;
        }
        local.push(User {
            id: if id.is_empty() { format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000")) } else { id },
            name, api_key, phrase_hash,
            quota_bytes: stone::auth::default_quota_bytes(),
            wallet_address: wallet, account_type: stone::auth::default_account_type(),
            org_id: String::new(), org_role: String::new(),
            discord_id: String::new(), discord_username: String::new(), bio: String::new(), updated_at: 0,
        });
        added += 1;
    }
    if added > 0 || updated > 0 { save_users(&local); println!("[sync] {added} neue + {updated} aktualisierte Nutzer von {peer_url}"); }
}

/// Holt pending PooledMessages von einem Peer und fügt sie in den lokalen
/// MessagePool + ChatIndex ein. Ermöglicht Dashboard-Nodes Nachrichten sofort
/// anzuzeigen, auch wenn sie nicht direkt vom Sender empfangen wurden.
pub async fn pull_message_pool_from_peer(
    node: &Arc<MasterNodeState>,
    peer_url: &str,
    chat_idx: &Arc<std::sync::Mutex<ChatIndex>>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/message-pool", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let msgs: Vec<PooledMessage> = match body.get("messages").and_then(|m| serde_json::from_value(m.clone()).ok()) {
        Some(v) => v,
        None => return,
    };

    if msgs.is_empty() { return; }

    let mut added = 0usize;
    let mut idx = chat_idx.lock().unwrap_or_else(|e| e.into_inner());
    for msg in &msgs {
        match node.message_pool.add_message(msg.clone()) {
            Ok(_) => {
                if idx.upsert_pool_message(msg) {
                    added += 1;
                }
            }
            Err(_) => { /* Duplikate sind ok */ }
        }
    }
    if added > 0 {
        stone::chat::save_chat_index(&idx);
        println!("[sync] 📬 {} Pending-Nachrichten von {peer_url} synchronisiert", added);
    }
}

/// Holt die DB-Metadaten von einem Peer und entscheidet via longest-chain-logik
/// ob die lokale DB von diesem Peer synchronisiert werden muss.
pub async fn pull_db_from_peer(node: &Arc<MasterNodeState>, peer_url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/db-metadata", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let remote_meta: DbMetadata = match serde_json::from_value(body.get("db_metadata").cloned().unwrap_or(serde_json::Value::Null)) {
        Ok(m) => m,
        Err(_) => return,
    };

    let local_meta = match DbMetadata::from_db(&node.db, &node.node_id) {
        Ok(m) => m,
        Err(e) => { eprintln!("[db-sync] Lokale DB-Metadaten Fehler: {e}"); return; }
    };

    match stone::database::decide_sync_direction(&local_meta, &remote_meta) {
        stone::database::SyncDecision::SyncFrom { node_id } => {
            println!(
                "[db-sync] Node {peer_url} has better DB ({} vs {} entries) — pulling users, orgs, peers, trust…",
                remote_meta.table_count, local_meta.table_count
            );
            sync_users_from_peer(&node, peer_url).await;
            sync_orgs_from_peer(&node, peer_url).await;
            sync_peers_from_peer(&node, peer_url).await;
            sync_trust_from_peer(&node, peer_url).await;
            println!("[db-sync] ✅ DB sync from {node_id} complete");
        }
        stone::database::SyncDecision::KeepLocal => {
            // Gleichstand — nichts tun
        }
        stone::database::SyncDecision::LocalIsBetter => {
            // Lokale DB ist besser — andere sollten von uns pullen
        }
    }
}

/// Holt die User-Liste von einem Peer und speichert sie in die lokale SQLite-DB.
async fn sync_users_from_peer(node: &Arc<MasterNodeState>, peer_url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/sync-db-users", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let users_raw = match body.get("users").and_then(|u| u.as_array()) { Some(arr) => arr, None => return };

    let mut users: Vec<User> = Vec::new();
    for ru in users_raw {
        let id = ru["id"].as_str().unwrap_or_default().to_string();
        let name = ru["name"].as_str().unwrap_or_default().to_string();
        let wallet = ru["wallet_address"].as_str().unwrap_or_default().to_string();
        let api_key = ru["api_key"].as_str().unwrap_or_default().to_string();
        let phrase_hash = ru["phrase_hash"].as_str().unwrap_or_default().to_string();
        if id.is_empty() { continue; }
        users.push(User {
            id, name, api_key, phrase_hash,
            quota_bytes: stone::auth::default_quota_bytes(),
            wallet_address: wallet, account_type: stone::auth::default_account_type(),
            org_id: String::new(), org_role: String::new(),
            discord_id: String::new(), discord_username: String::new(), bio: String::new(), updated_at: 0,
        });
    }

    if !users.is_empty() {
        if let Err(e) = node.db.save_users(&users) {
            eprintln!("[db-sync] Users speichern fehlgeschlagen: {e}");
        } else {
            println!("[db-sync] ✅ {} Users von {peer_url} in SQLite gespeichert", users.len());
        }
    }
}

/// Holt die Organisations-Liste und speichert sie in die lokale SQLite-DB.
async fn sync_orgs_from_peer(node: &Arc<MasterNodeState>, peer_url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/sync-db-organizations", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let orgs_list = match body.get("organizations") { Some(v) => v, None => return };
    let orgs: Vec<Organization> = match serde_json::from_value(orgs_list.clone()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[db-sync] ❌ Orgs-Deserialisierung von {peer_url} fehlgeschlagen: {e}");
            return;
        }
    };

    if !orgs.is_empty() {
        let count = orgs.len();
        if let Err(e) = node.db.save_organizations(&orgs) {
            eprintln!("[db-sync] Orgs speichern fehlgeschlagen: {e}");
        } else {
            println!("[db-sync] ✅ {count} Orgs von {peer_url} in SQLite gespeichert");
        }
    }
}

/// Holt die Peer-Liste und speichert sie in die lokale SQLite-DB.
async fn sync_peers_from_peer(node: &Arc<MasterNodeState>, peer_url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/sync-db-peers", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };
    let peers_raw = match body.get("peers") { Some(v) => v, None => return };
    let peers: Vec<PeerInfo> = match serde_json::from_value(peers_raw.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[db-sync] ❌ Peers-Deserialisierung von {peer_url} fehlgeschlagen: {e}");
            return;
        }
    };

    if !peers.is_empty() {
        let count = peers.len();
        if let Err(e) = node.db.save_peers(&peers) {
            eprintln!("[db-sync] Peers speichern fehlgeschlagen: {e}");
        } else {
            println!("[db-sync] ✅ {count} Peers von {peer_url} in SQLite gespeichert");
        }
    }
}

/// Holt Trust-Registry und -History und speichert sie in die lokale SQLite-DB.
async fn sync_trust_from_peer(node: &Arc<MasterNodeState>, peer_url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false))
        .build()
    { Ok(c) => c, Err(_) => return };

    let sync_url = to_sync_url(peer_url);
    let url = format!("{}/sync-db-trust", sync_url);
    let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => return };
    if !resp.status().is_success() { return; }
    let body: serde_json::Value = match resp.json().await { Ok(v) => v, Err(_) => return };

    let registry: Vec<TrustEntry> = match body.get("registry").and_then(|v| serde_json::from_value(v.clone()).ok()) {
        Some(r) => r,
        None => Vec::new(),
    };
    let history: Vec<TrustVote> = match body.get("history").and_then(|v| serde_json::from_value(v.clone()).ok()) {
        Some(h) => h,
        None => Vec::new(),
    };

    if !registry.is_empty() || !history.is_empty() {
        if let Err(e) = node.db.save_trust(&registry, &history) {
            eprintln!("[db-sync] Trust speichern fehlgeschlagen: {e}");
        } else {
            println!("[db-sync] ✅ {} trust entries + {} votes von {peer_url} in SQLite gespeichert",
                registry.len(), history.len());
        }
    }
}

pub fn sync_chain_accounts_to_users(node: &Arc<MasterNodeState>, users: &Arc<Mutex<Vec<User>>>) {
    let ledger = node.token_ledger.read().unwrap_or_else(|e| e.into_inner());
    let chain_accounts = ledger.all_registered_accounts();
    if chain_accounts.is_empty() { return; }
    let mut local = users.lock().unwrap_or_else(|e| e.into_inner());
    let mut added = 0usize;
    for (wallet, name) in chain_accounts {
        let exists = local.iter().any(|u| u.wallet_address == *wallet || (!u.api_key.is_empty() && ledger.account_api_key_hash(wallet).map_or(false, |h| h == u.api_key)));
        if exists { continue; }
        let api_key_hash = ledger.account_api_key_hash(wallet).unwrap_or_default().to_string();
        let id = format!("u-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"));
        local.push(User { id, name: name.clone(), bio: String::new(), api_key: api_key_hash.clone(), phrase_hash: api_key_hash, quota_bytes: stone::auth::default_quota_bytes(), wallet_address: wallet.clone(), account_type: stone::auth::default_account_type(), org_id: String::new(), org_role: String::new(), discord_id: String::new(), discord_username: String::new(), updated_at: chrono::Utc::now().timestamp() });
        added += 1;
    }
    if added > 0 { save_users(&local); println!("[sync] 📋 {added} Chain-Accounts in lokale User-Liste synchronisiert"); }
}

// ─── Bootstrap & Peer Health (benötigt von master_server.rs) ──────────────────

fn resolve_self_url() -> Option<String> {
    if let Ok(url) = std::env::var("STONE_PUBLIC_URL") { if !url.trim().is_empty() { return Some(url.trim().trim_end_matches('/').to_string()); } }
    if let Ok(ip) = std::env::var("STONE_PUBLIC_IP") { if !ip.trim().is_empty() { let default_http = if stone::network::is_mainnet() { 3180 } else { 3080 }; let port = std::env::var("STONE_HTTP_PORT").or_else(|_| std::env::var("STONE_PORT")).ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(default_http); return Some(format!("http://{}:{}", ip.trim(), if port == 8080 { default_http } else { port })); } }
    None
}

fn host_from_url(url: &str) -> Option<&str> { let s = url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("").split(':').next().unwrap_or("").trim(); if s.is_empty() { None } else { Some(s) } }
fn same_host_url(a: &str, b: &str) -> bool { match (host_from_url(a), host_from_url(b)) { (Some(ha), Some(hb)) => ha.eq_ignore_ascii_case(hb), _ => false } }
fn endpoint_from_url(url: &str) -> Option<(String, u16)> { let s = url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or(""); let mut parts = s.split(':'); let host = parts.next().unwrap_or("").to_ascii_lowercase(); if host.is_empty() { return None; } let port = parts.next().and_then(|v| v.parse::<u16>().ok()).unwrap_or(80); Some((host, port)) }
fn same_endpoint_url(a: &str, b: &str) -> bool { match (endpoint_from_url(a), endpoint_from_url(b)) { (Some(ea), Some(eb)) => ea == eb, _ => false } }
fn is_bootstrap_url(url: &str) -> bool { let configured = if let Ok(raw) = std::env::var("STONE_BOOTSTRAP_HTTP_URLS") { raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| s.trim_end_matches('/').to_string()).collect::<Vec<_>>() } else { stone::network::default_bootstrap_http_urls() }; configured.iter().any(|b| same_endpoint_url(url, b)) }

pub async fn bootstrap_announce(node: &Arc<MasterNodeState>) {
    let self_url = match resolve_self_url() { Some(url) => url, None => return };
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(std::env::var("STONE_INSECURE_SSL").map(|v| v == "1").unwrap_or(false)).build() { Ok(c) => c, Err(_) => return };
    let body = serde_json::json!({ "url": self_url, "peer_id": stone::network::read_peer_id(), "name": node.node_id });
    let configured = if let Ok(raw) = std::env::var("STONE_BOOTSTRAP_HTTP_URLS") { raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| s.trim_end_matches('/').to_string()).collect::<Vec<_>>() } else { stone::network::default_bootstrap_http_urls() };
    for url in configured { if !same_host_url(&self_url, &url) { let _ = client.post(&format!("{url}/api/v1/peers/register")).json(&body).send().await; } }
}

pub async fn fetch_missing_chunks(block: &stone::blockchain::Block, peer_base_url: &str, _api_key: &str) {
    let chunk_store = match ChunkStore::new() { Ok(s) => s, Err(_) => return };
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap_or_default();
    for doc in &block.documents { for cr in &doc.chunks { if chunk_store.read_chunk(&cr.hash).is_ok() { continue; } if let Ok(resp) = client.get(&format!("{}/api/v1/chunk/{}", peer_base_url.trim_end_matches('/'), cr.hash)).send().await { if resp.status().is_success() { if let Ok(b) = resp.bytes().await { let _ = chunk_store.write_chunk(&b); } } } } }
}

pub fn spawn_peer_health_task(node: Arc<MasterNodeState>) {
    let self_url = resolve_self_url();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop { interval.tick().await; let peers = node.get_peers(); if peers.is_empty() { continue; } 
            let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() { Ok(c) => c, Err(_) => continue }; 
            let now = chrono::Utc::now().timestamp();
            for peer in &peers { if let Some(ref me) = self_url { if same_host_url(&peer.url, me) { continue; } }
                let (ok, h) = match client.get(&format!("{}/api/v1/health", peer.url)).send().await { Ok(r) if r.status().is_success() => (true, r.json::<serde_json::Value>().await.ok().and_then(|v| v.get("block_height").and_then(|v| v.as_u64())).unwrap_or(0)), _ => (false, 0) };
                let mut all = node.peers.write().unwrap_or_else(|e| e.into_inner()); if let Some(p) = all.iter_mut().find(|p| p.url == peer.url) { if ok { p.status = PeerStatus::Healthy; p.last_seen = now; p.block_height = h; } else { p.status = PeerStatus::Unreachable; } } }
            let mut all = node.peers.write().unwrap_or_else(|e| e.into_inner()); let before = all.len();
            all.retain(|p| { if let Some(ref me) = self_url { if same_host_url(&p.url, me) { return false; } } if is_bootstrap_url(&p.url) { return true; } if p.last_seen == 0 { return p.status != PeerStatus::Unreachable; } now - p.last_seen < 3600 });
            if all.len() < before { let peers: Vec<_> = all.clone(); drop(all); super::state::save_peers(&peers); }
        }
    });
}