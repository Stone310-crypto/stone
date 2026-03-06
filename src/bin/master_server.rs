//! Stone Master Node – entry point
//!
//! Stellt eine vollständige REST + WebSocket API für die externe Web-UI bereit.
//! Kein lokales GUI – alle Steuerung erfolgt über die vom Benutzer entwickelte Webseite.
//!
//! API-Übersicht:
//!   GET    /api/v1/status                    – Node- & Chain-Status
//!   GET    /api/v1/health                    – Einfacher Healthcheck (kein Auth)
//!   GET    /api/v1/metrics                   – Master-Node-Metriken
//!   GET    /api/v1/blocks                    – Alle Blöcke (paginiert)
//!   GET    /api/v1/blocks/:index             – Block nach Index
//!   GET    /api/v1/documents                 – Alle aktiven Dokumente (admin)
//!   GET    /api/v1/documents/user/:user_id   – Dokumente eines Nutzers
//!   GET    /api/v1/documents/:doc_id         – Dokument per ID
//!   GET    /api/v1/documents/:doc_id/history – Versionshistorie
//!   GET    /api/v1/documents/:doc_id/data    – Roh-Bytes (Chunk-Rekonstruktion)
//!   POST   /api/v1/documents                       – Dokument hochladen (Multipart)
//!   POST   /api/v1/documents/:doc_id/transfer       – Eigentum übertragen
//!   DELETE /api/v1/documents/:doc_id               – Soft-Delete
//!   GET    /api/v1/peers                     – Peer-Liste
//!   POST   /api/v1/peers                     – Peer hinzufügen
//!   DELETE /api/v1/peers/:idx                – Peer entfernen
//!   POST   /api/v1/sync                      – Manuelle Synchronisation
//!   POST   /api/v1/auth/signup               – Neuen Nutzer anlegen (pusht an Peers)
//!   POST   /api/v1/auth/login                – Phrase-Login
//!   POST   /api/v1/admin/sync-users          – Nutzer-Liste von Peer empfangen & mergen
//!   GET    /api/v1/chain/verify              – Chain-Integrität prüfen
//!   GET    /ws                               – WebSocket Event-Stream

#[path = "server/mod.rs"]
mod server;

use std::{net::SocketAddr, sync::Arc};

use stone::{
    auth::load_users,
    blockchain::{data_dir, NodeRole},
    master_node::MasterNodeState,
    network::{start_network, NetworkHandle},
    storage::ChunkStore,
};

use server::{
    router::build_router,
    sync_router::build_sync_router,
    rate_limiter::RateLimits,
    state::{load_api_key, load_admin_key, load_peers_from_disk, load_trust_from_disk, AppState, HEARTBEAT_INTERVAL},
    sync::{fetch_missing_chunks, pull_from_peer, spawn_auto_sync_task},
};

#[tokio::main]
async fn main() {
    // ── .env laden (falls vorhanden) ──────────────────────────────────────────
    match dotenvy::dotenv() {
        Ok(path) => println!("[master] .env geladen: {}", path.display()),
        Err(dotenvy::Error::Io(_)) => { /* .env nicht gefunden – kein Fehler */ }
        Err(e) => eprintln!("[master] .env Warnung: {e}"),
    }

    std::fs::create_dir_all(data_dir()).expect("DATA_DIR anlegen");
    ChunkStore::new().expect("ChunkStore anlegen");

    let api_key = Arc::new(load_api_key());
    let admin_key = Arc::new(load_admin_key(&api_key));
    let node_id = std::env::var("STONE_NODE_ID")
        .or_else(|_| std::env::var("STONE_NODE_NAME"))
        .unwrap_or_else(|_| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "stone-master".into())
        });

    println!("[master] Node-ID: {node_id}");
    println!(
        "[master] API-Key geladen: {}...",
        &api_key[..8.min(api_key.len())]
    );

    // Master Node State initialisieren
    let node = MasterNodeState::new(node_id.clone(), api_key.as_ref().clone(), NodeRole::Master);

    // Gespeicherte Peers laden
    let saved_peers = load_peers_from_disk();
    if !saved_peers.is_empty() {
        println!("[master] {} Peer(s) aus Datei geladen", saved_peers.len());
        node.replace_peers(saved_peers);
    }

    // ── Bootstrap-Nodes laden ─────────────────────────────────────────────────
    // Quellen (in Priorität):
    //   1) STONE_BOOTSTRAP_NODES env (komma-separiert: "http://1.2.3.4:8080,http://5.6.7.8:8080")
    //   2) node_config.json → "bootstrap_nodes": ["http://..."]
    // Bootstrap-Nodes werden als Peers hinzugefügt (falls nicht schon vorhanden)
    {
        let mut bootstrap: Vec<String> = Vec::new();

        // Aus Env
        if let Ok(env_val) = std::env::var("STONE_BOOTSTRAP_NODES") {
            for url in env_val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                bootstrap.push(url);
            }
        }

        // Aus node_config.json
        if bootstrap.is_empty() {
            let config_path = format!("{}/../../node_config.json", stone::blockchain::data_dir());
            let config_path2 = "node_config.json".to_string();
            for path in &[&config_path, &config_path2] {
                if let Ok(data) = std::fs::read_to_string(path) {
                    if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&data) {
                        if let Some(nodes) = cfg.get("bootstrap_nodes").and_then(|v| v.as_array()) {
                            for n in nodes {
                                if let Some(url) = n.as_str() {
                                    bootstrap.push(url.to_string());
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }

        if !bootstrap.is_empty() {
            let existing_urls: std::collections::HashSet<String> = node
                .get_peers()
                .iter()
                .map(|p| p.url.clone())
                .collect();

            let mut added = 0;
            for url in &bootstrap {
                if !existing_urls.contains(url) {
                    let peer = stone::master_node::PeerInfo::new(url);
                    node.upsert_peer(peer);
                    added += 1;
                }
            }
            println!(
                "[master] 🌍 Bootstrap-Nodes: {} konfiguriert, {} neu hinzugefügt",
                bootstrap.len(),
                added
            );
        }
    }

    // Trust-Registry laden
    load_trust_from_disk(&node);
    {
        let summary = node.trust_summary();
        println!(
            "[master] Trust-Registry geladen: {} aktiv, {} pending, {} widerrufen",
            summary.active, summary.pending, summary.revoked
        );
    }

    let users = load_users();

    // On-Chain Account-Registry: Merge Chain-registrierte Accounts mit lokalen Users
    {
        let ledger = node.token_ledger.read().unwrap();
        if ledger.registered_account_count() > 0 {
            let mut local = users.lock().unwrap();
            let merged = stone::auth::rebuild_users_from_ledger(&ledger, &local);
            let chain_count = ledger.registered_account_count();
            *local = merged;
            stone::auth::save_users(&local);
            println!("[master] 📋 Users aus Chain-Registry geladen: {} Chain + {} lokal = {} gesamt",
                chain_count, local.len() - chain_count, local.len());
        }
    }

    // Hintergrund-Tasks starten
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    MasterNodeState::start_mining_loop(node.clone());
    spawn_auto_sync_task(node.clone(), api_key.clone(), users.clone());

    // Mempool-Eviction: abgelaufene TXs und known_ids periodisch bereinigen
    {
        let node_evict = node.clone();
        tokio::spawn(async move {
            let mut evict_interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut gc_counter: u64 = 0;
            loop {
                evict_interval.tick().await;
                node_evict.mempool.evict_expired();
                gc_counter += 1;
                // known_ids GC alle 5 Minuten
                if gc_counter % 5 == 0 {
                    node_evict.mempool.gc_known_ids();
                }
            }
        });
    }

    // P2P-Netzwerk starten (optional – deaktivieren via STONE_P2P_DISABLED=1)
    let network_handle: Option<NetworkHandle> =
        if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
            println!("[master] P2P-Netzwerk deaktiviert (STONE_P2P_DISABLED=1)");
            None
        } else {
            match start_network(None).await {
                Ok(handle) => {
                    println!(
                        "[master] P2P-Netzwerk gestartet – PeerId: {}",
                        handle.local_peer_id
                    );

                    {
                        let count = node.chain.lock().unwrap().blocks.len() as u64;
                        handle.set_chain_count(count).await;
                    }
                    // Chain-Referenz setzen damit P2P-Peers Blöcke direkt serviert bekommen
                    handle.set_chain_ref(node.chain.clone()).await;

                    {
                        use stone::network::NetworkEvent;
                        let mut event_rx = handle.subscribe();
                        let node_bg = node.clone();
                        let handle_bg = handle.clone();
                        let api_key_bg = api_key.clone();
                        tokio::spawn(async move {
                            while let Ok(event) = event_rx.recv().await {
                                match event {
                                NetworkEvent::BlockReceived { block, from_peer } => {
                                    let peer_urls: Vec<String> = {
                                        node_bg
                                            .get_peers()
                                            .into_iter()
                                            .filter(|p| p.is_healthy())
                                            .map(|p| p.url.clone())
                                            .collect()
                                    };
                                    for url in &peer_urls {
                                        fetch_missing_chunks(&block, url, &api_key_bg).await;
                                    }

                                    let poa_ok = {
                                        // Während Initial-Sync: PoA-Prüfung überspringen.
                                        // Die synced Blöcke wurden vom Netzwerk bereits akzeptiert.
                                        let syncing = !node_bg.metrics.initial_sync_done.load(
                                            std::sync::atomic::Ordering::Relaxed
                                        );
                                        if syncing {
                                            None // PoA bei Sync überspringen
                                        } else {
                                            let vs = node_bg.validator_set.read().unwrap();
                                            if vs.validators.is_empty() {
                                                None
                                            } else {
                                                let prev_hash = {
                                                    let chain = node_bg.chain.lock().unwrap();
                                                    chain.blocks.last().map(|b| b.hash.clone()).unwrap_or_else(|| "genesis".into())
                                                };
                                                let result = vs.verify_block_with_selection(
                                                    &block.hash,
                                                    &block.signer,
                                                    &block.validator_signature,
                                                    &prev_hash,
                                                    block.index,
                                                );
                                                Some(result.is_acceptable())
                                            }
                                        }
                                    };

                                    // Block-Akzeptanz in eigenem Scope (Lock vor await droppen)
                                    enum BlockResult {
                                        Accepted(u64),
                                        Stale,
                                        NeedsResync { idx: u64, from: String, err: String },
                                        Rejected,
                                        AlreadyKnown,
                                    }

                                    let result = {
                                        let mut chain = node_bg.chain.lock().unwrap();
                                        let already_known =
                                            chain.blocks.iter().any(|b| b.hash == block.hash);
                                        if already_known {
                                            BlockResult::AlreadyKnown
                                        } else {
                                            let idx = block.index;
                                            let block_txs = block.transactions.clone();
                                            match chain.accept_peer_block(*block, poa_ok) {
                                                Ok(_) => {
                                                    println!(
                                                        "[p2p] ✓ Block #{idx} von {from_peer} in Chain aufgenommen"
                                                    );
                                                    if !block_txs.is_empty() {
                                                        let mut ledger = node_bg.token_ledger.write().unwrap();
                                                        let receipts = ledger.apply_block_txs(&block_txs, idx);
                                                        if !receipts.is_empty() {
                                                            if let Err(e) = ledger.persist() {
                                                                eprintln!("[token] Ledger-Persist nach Peer-Block #{idx}: {e}");
                                                            }
                                                        }
                                                        for tx in &block_txs {
                                                            node_bg.mempool.mark_known(&tx.tx_id);
                                                            node_bg.mempool.remove_tx(&tx.tx_id);
                                                        }
                                                    }
                                                    BlockResult::Accepted(chain.blocks.len() as u64)
                                                }
                                                Err(ref e) if e.starts_with("Stale:") => BlockResult::Stale,
                                                Err(ref e)
                                                    if e.starts_with("Gap:")
                                                        || e.contains("previous_hash") =>
                                                {
                                                    let err = e.clone();
                                                    BlockResult::NeedsResync { idx, from: from_peer.clone(), err }
                                                }
                                                Err(e) => {
                                                    eprintln!("[p2p] Block #{idx} abgelehnt: {e}");
                                                    BlockResult::Rejected
                                                }
                                            }
                                        }
                                    }; // chain-Lock ist hier gedroppt

                                    match result {
                                        BlockResult::Accepted(count) => {
                                            handle_bg.set_chain_count(count).await;
                                            // Logging bei erstem Peer-Block, aber
                                            // initial_sync_done NICHT setzen – das macht
                                            // erst der 60-Sekunden-Timeout im Mining-Loop,
                                            // damit die PoA-Bypass-Phase den kompletten
                                            // initialen Sync abdeckt.
                                        }
                                        BlockResult::NeedsResync { idx, from, err } => {
                                            eprintln!(
                                                "[p2p] Block #{idx} von {from}: {err} → starte HTTP-Resync"
                                            );
                                            // PeerId → HTTP-URL auflösen
                                            let http_port = std::env::var("STONE_PORT")
                                                .ok()
                                                .and_then(|v| v.parse::<u16>().ok())
                                                .unwrap_or(8080);
                                            // Eigene öffentliche IP ermitteln, um Resync-an-sich-selbst zu vermeiden
                                            let own_public_ip = std::env::var("STONE_PUBLIC_IP").unwrap_or_default();
                                            let mut resolved_url: Option<String> = None;

                                            let net_peers = handle_bg.get_peers().await;
                                            if let Some(np) = net_peers.iter().find(|p| p.peer_id == from) {
                                                for addr in &np.addresses {
                                                    let parts: Vec<&str> = addr.split('/').collect();
                                                    for (i, part) in parts.iter().enumerate() {
                                                        if *part == "ip4" {
                                                            if let Some(ip) = parts.get(i + 1) {
                                                                // Localhost, Unspecified, Docker-Bridge
                                                                // und private Netzwerke überspringen
                                                                if *ip == "127.0.0.1"
                                                                    || *ip == "0.0.0.0"
                                                                    || ip.starts_with("172.")
                                                                    || ip.starts_with("10.")
                                                                    || ip.starts_with("192.168.")
                                                                    || ip.starts_with("169.254.")
                                                                {
                                                                    continue;
                                                                }
                                                                // Eigene öffentliche IP nicht als Peer-URL verwenden
                                                                if !own_public_ip.is_empty() && *ip == own_public_ip.as_str() {
                                                                    eprintln!("[sync] ⚠ Überspringe eigene IP {ip} bei Peer-URL-Auflösung");
                                                                    continue;
                                                                }
                                                                resolved_url = Some(format!("http://{}:{}", ip, http_port));
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    if resolved_url.is_some() { break; }
                                                }
                                                // Fallback: Wenn kein öffentliches IP gefunden,
                                                // nimm das erste nicht-localhost IP (z.B. Tailscale 100.x / privates Netz)
                                                if resolved_url.is_none() {
                                                    for addr in &np.addresses {
                                                        let parts: Vec<&str> = addr.split('/').collect();
                                                        for (i, part) in parts.iter().enumerate() {
                                                            if *part == "ip4" {
                                                                if let Some(ip) = parts.get(i + 1) {
                                                                    if *ip != "127.0.0.1"
                                                                        && *ip != "0.0.0.0"
                                                                        && !ip.starts_with("172.")
                                                                    {
                                                                        // Auch hier eigene IP ausschließen
                                                                        if !own_public_ip.is_empty() && *ip == own_public_ip.as_str() {
                                                                            continue;
                                                                        }
                                                                        resolved_url = Some(format!("http://{}:{}", ip, http_port));
                                                                        break;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if resolved_url.is_some() { break; }
                                                    }
                                                }
                                            }

                                            if let Some(url) = resolved_url {
                                                eprintln!("[sync] Resync via {url} (Peer {from})");
                                                let node_r = node_bg.clone();
                                                let key_r = api_key_bg.clone();
                                                tokio::spawn(async move {
                                                    pull_from_peer(&node_r, &url, &key_r).await;
                                                });
                                            } else {
                                                eprintln!("[sync] ⚠ Keine URL für Peer {from} – versuche alle bekannten Peers");
                                                let node_r = node_bg.clone();
                                                let key_r = api_key_bg.clone();
                                                tokio::spawn(async move {
                                                    let peers = node_r.get_peers();
                                                    for p in peers.iter().filter(|p| p.is_healthy()) {
                                                        pull_from_peer(&node_r, &p.url, &key_r).await;
                                                    }
                                                });
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                // ── Token-TX per Gossipsub empfangen → in Mempool ──
                                NetworkEvent::TxReceived { tx, from_peer } => {
                                    let ledger = node_bg.token_ledger.read().unwrap();
                                    match node_bg.mempool.add_tx(*tx, Some(&ledger)) {
                                        Ok(()) => {
                                            println!(
                                                "[p2p] 💸 TX von {from_peer} in Mempool aufgenommen (size={})",
                                                node_bg.mempool.pending_count()
                                            );
                                        }
                                        Err(e) => {
                                            let msg = format!("{e}");
                                            if !msg.contains("Duplikat") {
                                                eprintln!("[p2p] TX von {from_peer} abgelehnt: {e}");
                                            }
                                        }
                                    }
                                }

                                // ── Shard-Events ──────────────────────────────
                                NetworkEvent::ShardReceived { chunk_hash, shard_index, data, from_peer } => {
                                    // Shard wurde bereits in der P2P-Schicht gespeichert → nur Registry aktualisieren
                                    println!("[shard] ✅ Shard empfangen: {}[{}] ({} bytes) von {}", &chunk_hash[..8.min(chunk_hash.len())], shard_index, data.len(), &from_peer[..8.min(from_peer.len())]);
                                    let local_pid = handle_bg.local_peer_id.to_string();
                                    node_bg.shard_registry.add_holder(&chunk_hash, shard_index, &local_pid);
                                    node_bg.shard_registry.add_holder(&chunk_hash, shard_index, &from_peer);
                                    node_bg.shard_registry.persist();
                                }
                                NetworkEvent::ShardStored { chunk_hash, shard_index, peer_id, success, .. } => {
                                    if success {
                                        println!("[shard] ✅ Shard bestätigt: {}[{}] auf {}", &chunk_hash[..8.min(chunk_hash.len())], shard_index, &peer_id[..8.min(peer_id.len())]);
                                        node_bg.shard_registry.add_holder(&chunk_hash, shard_index, &peer_id);
                                        node_bg.shard_registry.persist();
                                    }
                                }
                                NetworkEvent::ShardRequestFailed { chunk_hash, shard_index, peer_id, error } => {
                                    eprintln!("[shard] ❌ Transfer fehlgeschlagen: {}[{}] → {}: {error}", &chunk_hash[..8.min(chunk_hash.len())], shard_index, &peer_id[..8.min(peer_id.len())]);
                                }

                                // ── Peer-Discovery → HTTP-Peer auto-registrieren ──
                                NetworkEvent::PeerIdentified { peer_id, addresses, .. } => {
                                    let http_port = std::env::var("STONE_PORT")
                                        .ok()
                                        .and_then(|v| v.parse::<u16>().ok())
                                        .unwrap_or(8080);
                                    let mut ip: Option<String> = None;
                                    for addr in &addresses {
                                        let parts: Vec<&str> = addr.split('/').collect();
                                        for (i, part) in parts.iter().enumerate() {
                                            if *part == "ip4" {
                                                if let Some(found_ip) = parts.get(i + 1) {
                                                    if *found_ip != "127.0.0.1" && *found_ip != "0.0.0.0" {
                                                        ip = Some(found_ip.to_string());
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        if ip.is_some() { break; }
                                    }
                                    if let Some(ip) = ip {
                                        let url = format!("http://{}:{}", ip, http_port);
                                        let mut peer_info = stone::master_node::PeerInfo::new(&url);
                                        peer_info.name = Some(peer_id[..12.min(peer_id.len())].to_string());
                                        node_bg.upsert_peer(peer_info);
                                        if let Ok(json) = serde_json::to_string_pretty(&node_bg.get_peers()) {
                                            let _ = std::fs::write(
                                                format!("{}/peers.json", stone::blockchain::data_dir()),
                                                json,
                                            );
                                        }
                                    }
                                }

                                // ── Update-Events ──────────────────────────────────
                                NetworkEvent::UpdateManifestReceived { manifest_json, from_peer } => {
                                    match serde_json::from_slice::<stone::updater::UpdateManifest>(&manifest_json) {
                                        Ok(manifest) => {
                                            println!(
                                                "[updater] 🆕 Update v{} von Peer {} empfangen",
                                                manifest.version,
                                                &from_peer[..12.min(from_peer.len())]
                                            );
                                            // TODO: integrate with state.updater when available
                                        }
                                        Err(e) => eprintln!("[updater] Manifest-Parse: {e}"),
                                    }
                                }

                                // ── Neuer Peer → Shard-Rebalancing ──────────
                                NetworkEvent::PeerConnected { peer_id, .. } => {
                                    println!("[master] 🔗 Peer verbunden: {}", &peer_id[..12.min(peer_id.len())]);
                                    let node_rb = node_bg.clone();
                                    let handle_rb = handle_bg.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        let local_peer_id = handle_rb.local_peer_id.clone();
                                        let shard_store = match stone::shard::ShardStore::new() {
                                            Ok(s) => s,
                                            Err(e) => {
                                                eprintln!("[rebalance] ShardStore-Fehler: {e}");
                                                return;
                                            }
                                        };
                                        let (migrated, failed) = stone::storage::rebalance_shards(
                                            &shard_store,
                                            &node_rb.shard_registry,
                                            &handle_rb,
                                            &local_peer_id,
                                        ).await;
                                        if migrated > 0 || failed > 0 {
                                            println!("[master] 📦 Rebalancing: {} migriert, {} fehlgeschlagen",
                                                migrated, failed);
                                        }
                                    });
                                }

                                // ── Peer getrennt → Registry bereinigen + Repair ──
                                NetworkEvent::PeerDisconnected { peer_id } => {
                                    eprintln!("[master] ⚡ Peer getrennt: {}", &peer_id[..12.min(peer_id.len())]);
                                    // Holder aus Shard-Registry entfernen
                                    node_bg.shard_registry.remove_holder(&peer_id);
                                    node_bg.shard_registry.persist();

                                    // Verzögerten Repair-Check starten:
                                    // Nach 30 Sek prüfen ob degradierte Chunks repariert werden müssen
                                    let node_repair = node_bg.clone();
                                    let handle_repair = handle_bg.clone();
                                    tokio::spawn(async move {
                                        // Warten, damit kurze Reconnects keinen unnötigen Repair triggern
                                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                                        // Prüfen ob der Peer inzwischen wieder da ist
                                        let still_gone = !handle_repair.connected_peers().await
                                            .iter().any(|p| p.peer_id == peer_id);
                                        if !still_gone {
                                            println!("[repair] Peer {} ist wieder da – kein Repair nötig",
                                                &peer_id[..12.min(peer_id.len())]);
                                            return;
                                        }

                                        // Degradierte Chunks finden und Shards an verbleibende Peers re-verteilen
                                        let local_peer_id = handle_repair.local_peer_id.clone();
                                        let shard_store = match stone::shard::ShardStore::new() {
                                            Ok(s) => s,
                                            Err(e) => {
                                                eprintln!("[repair] ShardStore: {e}");
                                                return;
                                            }
                                        };
                                        let (migrated, failed) = stone::storage::rebalance_shards(
                                            &shard_store,
                                            &node_repair.shard_registry,
                                            &handle_repair,
                                            &local_peer_id,
                                        ).await;
                                        if migrated > 0 || failed > 0 {
                                            println!("[repair] 🔧 Repair nach Peer-Verlust: {} migriert, {} fehlgeschlagen",
                                                migrated, failed);
                                        }
                                    });
                                }

                                _ => {} // Listening etc.
                                }
                            }
                        });
                    }

                    Some(handle)
                }
                Err(e) => {
                    eprintln!("[master] P2P-Netzwerk konnte nicht gestartet werden: {e}");
                    None
                }
            }
        };

    let rate_limits = Arc::new(RateLimits::new());

    // Rate-Limiter Cleanup-Task (alle 5 Minuten)
    {
        let rl = rate_limits.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                rl.cleanup_all();
            }
        });
    }

    // ── Periodischer Shard-Health-Check (alle 5 Minuten) ─────────────────────
    // Prüft ob Shards degradiert/kritisch sind und repariert automatisch
    // durch Re-Verteilung an verfügbare Peers.
    if let Some(ref network) = network_handle {
        let node_health = node.clone();
        let handle_health = network.clone();
        tokio::spawn(async move {
            // Erst 2 Minuten nach Start warten (P2P muss sich stabilisieren)
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let mut health_interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                health_interval.tick().await;

                let connected = handle_health.connected_peers().await;
                if connected.is_empty() {
                    continue; // Keine Peers → nichts zu tun
                }

                // Alle Chunks in der Registry durchgehen
                let chunks = node_health.shard_registry.all_chunks();
                let ec_k = stone::shard::DEFAULT_EC_K;
                let mut healthy = 0u64;
                let mut degraded = 0u64;
                let mut critical = 0u64;

                for chunk_hash in &chunks {
                    let (status, _count) = node_health.shard_registry.chunk_health(chunk_hash, ec_k);
                    match status {
                        "healthy" => healthy += 1,
                        "degraded" => degraded += 1,
                        "critical" => critical += 1,
                        _ => {}
                    }
                }

                if degraded > 0 || critical > 0 {
                    eprintln!(
                        "[health] ⚠ Shard-Status: {} healthy, {} degraded, {} critical – starte Repair",
                        healthy, degraded, critical
                    );

                    let local_peer_id = handle_health.local_peer_id.clone();
                    let shard_store = match stone::shard::ShardStore::new() {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[health] ShardStore: {e}");
                            continue;
                        }
                    };
                    let (migrated, failed) = stone::storage::rebalance_shards(
                        &shard_store,
                        &node_health.shard_registry,
                        &handle_health,
                        &local_peer_id,
                    ).await;
                    if migrated > 0 || failed > 0 {
                        println!(
                            "[health] 🔧 Auto-Repair: {} migriert, {} fehlgeschlagen",
                            migrated, failed
                        );
                    }
                } else if !chunks.is_empty() {
                    println!("[health] ✅ Alle {} Chunks healthy", healthy);
                }
            }
        });
    }

    let state = AppState {
        node: node.clone(),
        users,
        api_key: api_key.clone(),
        admin_key,
        network: network_handle,
        rate_limits,
        updater: Arc::new(std::sync::RwLock::new({
            let mut um = stone::updater::UpdateManager::new(&stone::blockchain::data_dir());
            um.load_persisted_update();
            um
        })),
        orgs: Arc::new(std::sync::Mutex::new(stone::organization::load_orgs())),
        chat_index: {
            let mut idx = stone::chat::load_chat_index();
            // Chat-Index aus der Chain aufbauen/aktualisieren
            let chain = node.chain.lock().unwrap();
            if chain.blocks.len() as u64 > idx.last_indexed_block {
                let new_blocks: Vec<_> = chain.blocks.iter()
                    .skip(idx.last_indexed_block as usize)
                    .collect();
                idx.index_new_blocks(&new_blocks);
                let _ = stone::chat::save_chat_index(&idx);
            }
            Arc::new(std::sync::Mutex::new(idx))
        },
        contacts: Arc::new(std::sync::Mutex::new(stone::chat::load_contacts())),
        challenge_store: stone::auth::ChallengeStore::new(),
        qr_login_store: stone::auth::QrLoginStore::new(),
    };

    let router = build_router(state.clone());

    let preferred_port: u16 = std::env::var("STONE_HTTP_PORT")
        .or_else(|_| std::env::var("STONE_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    // ── Public Sync Port (kein Auth, für Node-zu-Node Kommunikation) ─────
    let sync_port: u16 = std::env::var("STONE_SYNC_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4002);

    let sync_router = build_sync_router(state);
    let sync_listener = bind_with_fallback(sync_port).await;
    println!("[master] 🌐 Sync-Port auf 0.0.0.0:{sync_port} (öffentlich, kein Auth)");
    tokio::spawn(async move {
        axum::serve(sync_listener, sync_router)
            .await
            .expect("Sync-Server Fehler");
    });

    let listener = bind_with_fallback(preferred_port).await;
    let bound_port = listener.local_addr().unwrap().port();
    println!("[master] HTTP auf 0.0.0.0:{bound_port} (Admin-API)");
    println!("[master] Stone Master Node läuft auf http://0.0.0.0:{bound_port}");
    println!("[master] Web-UI kann sich via ws://0.0.0.0:{bound_port}/ws verbinden");
    axum::serve(listener, router).await.expect("HTTP-Server Fehler");
}

/// Bindet an `preferred_port`. Bei Port-Konflikt: harter Fehler statt zufälligem Port.
async fn bind_with_fallback(preferred_port: u16) -> tokio::net::TcpListener {
    let addr = SocketAddr::from(([0, 0, 0, 0], preferred_port));
    match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("[master] ❌ Port {preferred_port} ist bereits belegt!");
            eprintln!("[master] Lösungen:");
            eprintln!("[master]   1) Alte Prozesse beenden:  pkill -f stone-master");
            eprintln!(
                "[master]   2) Anderen Port nutzen:    STONE_PORT={} in .env",
                preferred_port + 1
            );
            eprintln!("[master]   3) Belegenden Prozess prüfen: lsof -i :{preferred_port}");
            std::process::exit(1);
        }
        Err(e) => panic!("TCP-Bind fehlgeschlagen: {e}"),
    }
}
