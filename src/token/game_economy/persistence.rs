// ─── Persistence (Column Families) ────────────────────────────────────────────


use super::*;

impl GameEconomyStore {
    // ═════════════════════════════════════════════════════════════════════
    //  §10 Persistence (Column Families)
    // ═════════════════════════════════════════════════════════════════════

    const LEGACY_DB_KEY: &'static [u8] = b"game_economy_store_v2";

    /// Persistiert alle Game-Economy-Daten in dedizierte Column Families.
    /// Jede Entity-Klasse lebt in einer eigenen CF statt als monolithischer Blob.
    pub fn persist(&self) -> Result<(), String> {
        let db = crate::token::open_token_db()
            .map_err(|e| format!("game-economy DB: {e}"))?;

        // ── game_registry CF: Games + Consent ────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_REGISTRY) {
            for (id, game) in &self.registered_games {
                let key = format!("game/{}", id);
                let val = serde_json::to_vec(game).map_err(|e| format!("serialize game: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put game: {e}"))?;
            }
            for (id, cr) in &self.consent_requests {
                let key = format!("consent/{}", id);
                let val = serde_json::to_vec(cr).map_err(|e| format!("serialize consent: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put consent: {e}"))?;
            }
            for (game_id, secret) in &self.owner_totp_secrets {
                let key = format!("totp/{}", game_id);
                db.put_cf(cf, key.as_bytes(), secret.as_bytes()).map_err(|e| format!("put totp: {e}"))?;
            }
        }

        // ── game_wallets CF ──────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_WALLETS) {
            for (addr, gw) in &self.game_wallets {
                let key = format!("wallet/{}", addr);
                let val = serde_json::to_vec(gw).map_err(|e| format!("serialize wallet: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put wallet: {e}"))?;
            }
        }

        // ── game_items CF ────────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_ITEMS) {
            for (id, item) in &self.items {
                let key = format!("item/{}", id);
                let val = serde_json::to_vec(item).map_err(|e| format!("serialize item: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put item: {e}"))?;
            }
        }

        // ── game_market CF: Listings + Offers + Price History + Shop ─
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_MARKET) {
            for (id, listing) in &self.listings {
                let key = format!("listing/{}", id);
                let val = serde_json::to_vec(listing).map_err(|e| format!("serialize listing: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put listing: {e}"))?;
            }
            for (id, offer) in &self.offers {
                let key = format!("offer/{}", id);
                let val = serde_json::to_vec(offer).map_err(|e| format!("serialize offer: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put offer: {e}"))?;
            }
            for (item_id, entries) in &self.price_history {
                let key = format!("price/{}", item_id);
                let val = serde_json::to_vec(entries).map_err(|e| format!("serialize price: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put price: {e}"))?;
            }
            for (id, shop_item) in &self.shop_items {
                let key = format!("shop/{}", id);
                let val = serde_json::to_vec(shop_item).map_err(|e| format!("serialize shop: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put shop: {e}"))?;
            }
        }

        // ── game_sessions CF: Sessions + Wallet Links ────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_SESSIONS) {
            for (token, session) in &self.sessions {
                let key = format!("session/{}", token);
                let val = serde_json::to_vec(session).map_err(|e| format!("serialize session: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put session: {e}"))?;
            }
            for (link_key, link) in &self.wallet_links {
                let key = format!("link/{}", link_key);
                let val = serde_json::to_vec(link).map_err(|e| format!("serialize link: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put link: {e}"))?;
            }
        }

        // ── game_audit CF ────────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_AUDIT) {
            for entry in &self.audit_log {
                let key = format!("audit/{}", entry.entry_id);
                let val = serde_json::to_vec(entry).map_err(|e| format!("serialize audit: {e}"))?;
                db.put_cf(cf, key.as_bytes(), &val).map_err(|e| format!("put audit: {e}"))?;
            }
        }

        // JSON-File-Backup (schneller Fallback bei DB-Problemen)
        let json = serde_json::to_vec(self).map_err(|e| format!("serialize full: {e}"))?;
        let json_path = format!("{}/game_economy.json", crate::blockchain::data_dir());
        if let Err(e) = std::fs::write(&json_path, &json) {
            eprintln!("[game-economy] ⚠️  JSON-Backup fehlgeschlagen: {e}");
        }

        Ok(())
    }

    /// Lädt den Game-Economy-Store: erst aus Column Families,
    /// dann Fallback auf alten monolithischen Blob (default CF / JSON).
    pub fn load() -> Self {
        let db = match crate::token::open_token_db() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("[game-economy] ⚠️  DB nicht verfügbar: {e}");
                return Self::load_json_fallback();
            }
        };

        // Prüfe ob in den neuen CFs bereits Daten liegen
        let has_cf_data = db.cf_handle(crate::token::TOKEN_CF_GAME_REGISTRY)
            .and_then(|cf| db.prefix_iterator_cf(cf, b"game/").next())
            .is_some();

        if has_cf_data {
            return Self::load_from_cfs(db);
        }

        // Fallback: alter monolithischer Blob
        if let Ok(Some(bytes)) = db.get(Self::LEGACY_DB_KEY) {
            if let Ok(store) = serde_json::from_slice::<Self>(&bytes) {
                println!("[game-economy] 📂 Aus Legacy-Blob geladen (wird bei nächstem Persist migriert)");
                return store;
            }
        }

        Self::load_json_fallback()
    }

    /// Lädt aus den dedizierten Column Families.
    fn load_from_cfs(db: &rocksdb::DB) -> Self {
        let mut store = Self::new();

        // ── game_registry CF ─────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_REGISTRY) {
            for item in db.prefix_iterator_cf(cf, b"game/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("game/") { break; }
                        if let Ok(game) = serde_json::from_slice::<RegisteredGame>(&value) {
                            store.registered_games.insert(game.game_id.clone(), game);
                        }
                    }
                    Err(_) => break,
                }
            }
            for item in db.prefix_iterator_cf(cf, b"consent/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("consent/") { break; }
                        if let Ok(cr) = serde_json::from_slice::<ConsentRequest>(&value) {
                            store.consent_requests.insert(cr.request_id.clone(), cr);
                        }
                    }
                    Err(_) => break,
                }
            }
            for item in db.prefix_iterator_cf(cf, b"totp/") {
                match item {
                    Ok((key, value)) => {
                        let key_str = String::from_utf8_lossy(&key);
                        if !key_str.starts_with("totp/") { break; }
                        let game_id = key_str.trim_start_matches("totp/").to_string();
                        if let Ok(secret) = String::from_utf8(value.to_vec()) {
                            store.owner_totp_secrets.insert(game_id, secret);
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // ── game_wallets CF ──────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_WALLETS) {
            for item in db.prefix_iterator_cf(cf, b"wallet/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("wallet/") { break; }
                        if let Ok(gw) = serde_json::from_slice::<GameWallet>(&value) {
                            store.game_wallets.insert(gw.game_wallet.clone(), gw);
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // ── game_items CF ────────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_ITEMS) {
            for item in db.prefix_iterator_cf(cf, b"item/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("item/") { break; }
                        if let Ok(gi) = serde_json::from_slice::<GameItem>(&value) {
                            store.items.insert(gi.item_id.clone(), gi);
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // ── game_market CF ───────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_MARKET) {
            for item in db.prefix_iterator_cf(cf, b"listing/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("listing/") { break; }
                        if let Ok(l) = serde_json::from_slice::<MarketListing>(&value) {
                            store.listings.insert(l.listing_id.clone(), l);
                        }
                    }
                    Err(_) => break,
                }
            }
            for item in db.prefix_iterator_cf(cf, b"offer/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("offer/") { break; }
                        if let Ok(o) = serde_json::from_slice::<MarketOffer>(&value) {
                            store.offers.insert(o.offer_id.clone(), o);
                        }
                    }
                    Err(_) => break,
                }
            }
            for item in db.prefix_iterator_cf(cf, b"price/") {
                match item {
                    Ok((key, value)) => {
                        let key_str = String::from_utf8_lossy(&key);
                        if !key_str.starts_with("price/") { break; }
                        let item_id = key_str.trim_start_matches("price/").to_string();
                        if let Ok(entries) = serde_json::from_slice::<Vec<PriceHistoryEntry>>(&value) {
                            store.price_history.insert(item_id, entries);
                        }
                    }
                    Err(_) => break,
                }
            }
            for item in db.prefix_iterator_cf(cf, b"shop/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("shop/") { break; }
                        if let Ok(si) = serde_json::from_slice::<ShopItem>(&value) {
                            store.shop_items.insert(si.shop_item_id.clone(), si);
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // ── game_sessions CF ─────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_SESSIONS) {
            for item in db.prefix_iterator_cf(cf, b"session/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("session/") { break; }
                        if let Ok(s) = serde_json::from_slice::<SdkSession>(&value) {
                            store.sessions.insert(s.token.clone(), s);
                        }
                    }
                    Err(_) => break,
                }
            }
            for item in db.prefix_iterator_cf(cf, b"link/") {
                match item {
                    Ok((key, value)) => {
                        let key_str = String::from_utf8_lossy(&key);
                        if !key_str.starts_with("link/") { break; }
                        let link_key = key_str.trim_start_matches("link/").to_string();
                        if let Ok(link) = serde_json::from_slice::<WalletLink>(&value) {
                            store.wallet_links.insert(link_key, link);
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // ── game_audit CF ────────────────────────────────────────────
        if let Some(cf) = db.cf_handle(crate::token::TOKEN_CF_GAME_AUDIT) {
            for item in db.prefix_iterator_cf(cf, b"audit/") {
                match item {
                    Ok((key, value)) => {
                        if !String::from_utf8_lossy(&key).starts_with("audit/") { break; }
                        if let Ok(entry) = serde_json::from_slice::<AuditLogEntry>(&value) {
                            store.audit_log.push(entry);
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        let total = store.registered_games.len() + store.game_wallets.len()
            + store.items.len() + store.listings.len();
        if total > 0 {
            println!(
                "[game-economy] 📂 CF geladen: {} Games, {} Wallets, {} Items, {} Listings, {} Sessions, {} Audit",
                store.registered_games.len(), store.game_wallets.len(),
                store.items.len(), store.listings.len(),
                store.sessions.len(), store.audit_log.len(),
            );
        }

        store
    }

    /// Fallback: Lädt den Store aus der JSON-Backup-Datei.
    fn load_json_fallback() -> Self {
        let json_path = format!("{}/game_economy.json", crate::blockchain::data_dir());
        if let Ok(bytes) = std::fs::read(&json_path) {
            if let Ok(store) = serde_json::from_slice::<Self>(&bytes) {
                println!("[game-economy] 📂 Aus JSON-Backup geladen");
                return store;
            }
            eprintln!("[game-economy] ⚠️  JSON-Backup Deserialize fehlgeschlagen");
        }
        eprintln!("[game-economy] ⚠️  Kein Datenbestand gefunden – starte leer");
        Self::new()
    }
}
