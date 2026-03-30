// ─── Items & Marktplatz ───────────────────────────────────────────────────────

use chrono::Utc;
use rust_decimal::Decimal;

use super::*;

impl GameEconomyStore {
    // ═════════════════════════════════════════════════════════════════════
    //  §4 NFT Items
    // ═════════════════════════════════════════════════════════════════════

    pub fn mint_item(
        &mut self,
        item_id: &str,
        name: &str,
        description: &str,
        category: &str,
        rarity: ItemRarity,
        owner: &str,
        game_id: &str,
        creator: &str,
        metadata: HashMap<String, serde_json::Value>,
        transferable: bool,
    ) -> Result<GameItem, GameEconomyError> {
        if self.items.contains_key(item_id) {
            return Err(GameEconomyError::AlreadyExists { what: format!("Item {item_id}") });
        }

        let item = GameItem {
            item_id: item_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            category: category.to_string(),
            rarity,
            owner: owner.to_string(),
            game_id: game_id.to_string(),
            creator: creator.to_string(),
            metadata,
            created_at: Utc::now().timestamp(),
            transferable,
            burned: false,
        };

        self.items.insert(item_id.to_string(), item.clone());
        self.audit(game_id, creator, "mint_item", serde_json::json!({
            "item_id": item_id, "owner": owner,
        }), true);
        Ok(item)
    }

    pub fn items_of(&self, owner: &str) -> Vec<&GameItem> {
        self.items.values().filter(|i| i.owner == owner && !i.burned).collect()
    }

    pub fn transfer_item(
        &mut self,
        item_id: &str,
        from: &str,
        to: &str,
    ) -> Result<(), GameEconomyError> {
        let item = self.items.get_mut(item_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Item {item_id}") })?;

        if item.owner != from {
            return Err(GameEconomyError::NotOwner {
                item_id: item_id.to_string(),
                expected: from.to_string(),
                actual: item.owner.clone(),
            });
        }

        if !item.transferable {
            return Err(GameEconomyError::NotTransferable { item_id: item_id.to_string() });
        }

        if item.burned {
            return Err(GameEconomyError::ItemBurned { item_id: item_id.to_string() });
        }

        let game_id = item.game_id.clone();
        item.owner = to.to_string();
        self.audit(&game_id, from, "transfer_item", serde_json::json!({
            "item_id": item_id, "to": to,
        }), true);
        Ok(())
    }

    pub fn burn_item(&mut self, item_id: &str, owner: &str) -> Result<(), GameEconomyError> {
        let item = self.items.get_mut(item_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Item {item_id}") })?;

        if item.owner != owner {
            return Err(GameEconomyError::NotOwner {
                item_id: item_id.to_string(),
                expected: owner.to_string(),
                actual: item.owner.clone(),
            });
        }

        if item.burned {
            return Err(GameEconomyError::ItemBurned { item_id: item_id.to_string() });
        }

        item.burned = true;
        let game_id = item.game_id.clone();
        for listing in self.listings.values_mut() {
            if listing.item_id == item_id && listing.status == ListingStatus::Active {
                listing.status = ListingStatus::Cancelled;
            }
        }

        self.audit(&game_id, owner, "burn_item", serde_json::json!({
            "item_id": item_id,
        }), true);
        Ok(())
    }

    // ═════════════════════════════════════════════════════════════════════
    //  §5 Marktplatz
    // ═════════════════════════════════════════════════════════════════════

    pub fn list_item(
        &mut self,
        seller: &str,
        item_id: &str,
        price: Decimal,
        expires_at: Option<i64>,
    ) -> Result<MarketListing, GameEconomyError> {
        let item = self.items.get(item_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Item {item_id}") })?;

        if item.owner != seller {
            return Err(GameEconomyError::NotOwner {
                item_id: item_id.to_string(),
                expected: seller.to_string(),
                actual: item.owner.clone(),
            });
        }

        if !item.transferable || item.burned {
            return Err(GameEconomyError::NotTransferable { item_id: item_id.to_string() });
        }

        if price <= Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount { reason: "Preis muss positiv sein".into() });
        }

        let already_listed = self.listings.values()
            .any(|l| l.item_id == item_id && l.status == ListingStatus::Active);
        if already_listed {
            return Err(GameEconomyError::AlreadyExists {
                what: format!("Aktives Listing für Item {item_id}"),
            });
        }

        let seller_count = self.listings.values()
            .filter(|l| l.seller == seller && l.status == ListingStatus::Active)
            .count();
        if seller_count >= MAX_LISTINGS_PER_WALLET {
            return Err(GameEconomyError::LimitReached { limit: MAX_LISTINGS_PER_WALLET });
        }

        let listing_id = generate_id("LST", item_id);
        let now = Utc::now().timestamp();

        let listing = MarketListing {
            listing_id: listing_id.clone(),
            item_id: item_id.to_string(),
            seller: seller.to_string(),
            price,
            status: ListingStatus::Active,
            created_at: now,
            expires_at,
        };

        self.listings.insert(listing_id, listing.clone());
        Ok(listing)
    }

    pub fn delist_item(&mut self, listing_id: &str, seller: &str) -> Result<(), GameEconomyError> {
        let listing = self.listings.get_mut(listing_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Listing {listing_id}") })?;

        if listing.seller != seller {
            return Err(GameEconomyError::NotOwner {
                item_id: listing.item_id.clone(),
                expected: seller.to_string(),
                actual: listing.seller.clone(),
            });
        }

        if listing.status != ListingStatus::Active {
            return Err(GameEconomyError::InvalidState {
                reason: "Listing ist nicht aktiv".into(),
            });
        }

        listing.status = ListingStatus::Cancelled;
        Ok(())
    }

    /// Item kaufen. Gibt (fee, seller_amount, seller_wallet) zurück.
    pub fn buy_item(
        &mut self,
        listing_id: &str,
        buyer: &str,
    ) -> Result<(Decimal, Decimal, String), GameEconomyError> {
        let listing = self.listings.get(listing_id).cloned()
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Listing {listing_id}") })?;

        if listing.status != ListingStatus::Active {
            return Err(GameEconomyError::InvalidState { reason: "Listing ist nicht aktiv".into() });
        }

        if listing.seller == buyer {
            return Err(GameEconomyError::InvalidState { reason: "Eigene Items können nicht gekauft werden".into() });
        }

        if let Some(exp) = listing.expires_at {
            if Utc::now().timestamp() > exp {
                let l = self.listings.get_mut(&listing.listing_id).unwrap();
                l.status = ListingStatus::Expired;
                return Err(GameEconomyError::InvalidState { reason: "Listing ist abgelaufen".into() });
            }
        }

        let fee = (listing.price * Decimal::from(MARKETPLACE_FEE_PCT) / Decimal::from(MARKETPLACE_FEE_BASE)).round_dp(8);
        let seller_amount = listing.price - fee;

        self.transfer_item(&listing.item_id, &listing.seller, buyer)?;

        let l = self.listings.get_mut(&listing.listing_id).unwrap();
        l.status = ListingStatus::Sold {
            buyer: buyer.to_string(),
            sold_at: Utc::now().timestamp(),
        };

        self.price_history.entry(listing.item_id.clone()).or_default().push(PriceHistoryEntry {
            item_id: listing.item_id.clone(),
            price: listing.price,
            seller: listing.seller.clone(),
            buyer: buyer.to_string(),
            timestamp: Utc::now().timestamp(),
        });

        Ok((fee, seller_amount, listing.seller.clone()))
    }

    pub fn place_offer(
        &mut self,
        listing_id: &str,
        bidder: &str,
        amount: Decimal,
    ) -> Result<MarketOffer, GameEconomyError> {
        let listing = self.listings.get(listing_id)
            .ok_or_else(|| GameEconomyError::NotFound { what: format!("Listing {listing_id}") })?;

        if listing.status != ListingStatus::Active {
            return Err(GameEconomyError::InvalidState { reason: "Listing ist nicht aktiv".into() });
        }

        if amount <= Decimal::ZERO {
            return Err(GameEconomyError::InvalidAmount { reason: "Gebot muss positiv sein".into() });
        }

        let offer_id = generate_id("OFR", &format!("{listing_id}:{bidder}"));
        let offer = MarketOffer {
            offer_id: offer_id.clone(),
            listing_id: listing_id.to_string(),
            bidder: bidder.to_string(),
            amount,
            created_at: Utc::now().timestamp(),
            accepted: false,
        };

        self.offers.insert(offer_id, offer.clone());
        Ok(offer)
    }

    pub fn active_listings(&self, category: Option<&str>) -> Vec<ListingWithItem> {
        self.listings.values()
            .filter(|l| l.status == ListingStatus::Active)
            .filter_map(|l| {
                let item = self.items.get(&l.item_id)?;
                if let Some(cat) = category {
                    if item.category != cat { return None; }
                }
                Some(ListingWithItem { listing: l.clone(), item: item.clone() })
            })
            .collect()
    }

    pub fn floor_price(&self, category: &str) -> Option<(Decimal, String)> {
        self.listings.values()
            .filter(|l| l.status == ListingStatus::Active)
            .filter_map(|l| {
                let item = self.items.get(&l.item_id)?;
                if item.category == category { Some((l.price, l.listing_id.clone())) } else { None }
            })
            .min_by_key(|(p, _)| *p)
    }

}
