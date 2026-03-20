//! Router assembly and CORS configuration.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::Method,
    routing::{delete, get, post},
};
use tower_http::cors::{Any, CorsLayer};

use super::state::{AppState, MAX_UPLOAD_BYTES};
use super::handlers::{
    auth::{handle_login, handle_signup, handle_sync_users, handle_wallet_claim,
           handle_request_challenge, handle_verify_challenge,
           handle_qr_create, handle_qr_status, handle_qr_approve},
    blocks::{handle_get_block, handle_list_blocks},
    chunks::handle_get_chunk,
    documents::{
        handle_delete_document, handle_document_history, handle_get_document,
        handle_get_document_data, handle_list_documents, handle_list_user_documents,
        handle_patch_document, handle_search_documents, handle_transfer_document,
        handle_upload_document,
    },
    mining::{
        handle_mining_status, handle_mining_throttle, handle_mining_withdraw,
        handle_mining_stake, handle_mining_unstake,
        handle_bind_mining_wallet, handle_mining_wallet_info,
        handle_mining_template, handle_mining_submit,
        handle_mining_report, handle_mining_remote_status,
    },
    calls::{handle_send_signal, handle_get_signals},
    audio_relay::handle_audio_relay,
    chat::{
        handle_chat_conversations, handle_chat_messages, handle_chat_pending,
        handle_chat_proof,
        handle_chat_resolve, handle_chat_resolve_public, handle_chat_send,
        handle_add_contact, handle_list_contacts, handle_remove_contact,
        handle_chat_send_coins, handle_chat_request_coins,
        handle_send_contact_request, handle_list_contact_requests,
        handle_accept_contact_request, handle_decline_contact_request,
    },
    chat_policy::{
        handle_chat_policy_status, handle_chat_policy_message,
        handle_chat_report, handle_chat_reports, handle_chat_report_vote,
    },
    groups::{
        handle_create_group, handle_list_groups, handle_get_group,
        handle_group_send, handle_group_messages,
        handle_add_group_member, handle_remove_group_member,
    },
    orgs::{
        handle_accept_invite, handle_create_channel, handle_create_org,
        handle_decline_invite, handle_get_chat, handle_get_org, handle_invite,
        handle_leave_org, handle_list_orgs, handle_my_invites,
        handle_remove_member, handle_send_message, handle_set_role,
    },
    p2p::{
        handle_p2p_config, handle_p2p_dial, handle_p2p_info, handle_p2p_peers,
        handle_p2p_ping, handle_p2p_precommit, handle_p2p_proposal, handle_p2p_status,
    },
    peers::{handle_add_peer, handle_list_peers, handle_register_peer, handle_remove_peer, handle_sync},
    poa::{
        handle_add_validator, handle_cast_vote, handle_consensus_status,
        handle_detect_forks, handle_list_checkpoints, handle_list_validators,
        handle_receive_checkpoint, handle_remove_validator,
        handle_resolve_fork, handle_set_validator_active, handle_slashing_info,
        handle_slashing_validator, handle_validator_self,
    },
    status::{handle_health, handle_info, handle_metrics, handle_network_stats, handle_node_list, handle_shard_health, handle_status, handle_verify},
    token::{
        handle_token_accounts, handle_token_faucet, handle_token_history,
        handle_token_pending, handle_token_send, handle_token_send_authenticated,

        handle_token_supply,
        handle_token_transfer, handle_tx_status, handle_wallet_balance, handle_wallet_create,
        handle_wallet_info, handle_wallet_rotations,
        handle_staking_info, handle_staking_pool, handle_staker_info,
        handle_mempool_sync,
        handle_ledger_rebuild, handle_admin_airdrop,
    },
    trust::{
        handle_trust_approve, handle_trust_check, handle_trust_history,
        handle_trust_pending, handle_trust_registry, handle_trust_request,
        handle_trust_revoke,
    },
    updates::{
        handle_update_chunk, handle_update_config, handle_update_download,
        handle_update_install, handle_update_publish, handle_update_status,
    },
    game::{
        // SDK Developer
        handle_sdk_register, handle_sdk_quick_register,
        handle_sdk_game_info, handle_sdk_game_status,
        // SDK Consent
        handle_sdk_consent_request, handle_sdk_consent_pending,
        handle_sdk_consent_approve, handle_sdk_consent_reject,
        // SDK Wallet
        handle_sdk_wallet_create, handle_sdk_wallet_link, handle_sdk_wallet_balance,
        handle_sdk_wallet_transactions, handle_sdk_wallet_send,
        handle_sdk_wallet_withdraw, handle_sdk_nft_inventory,
        handle_sdk_wallet_freeze, handle_sdk_wallet_unfreeze,
        handle_sdk_wallet_set_limit,
        // SDK TX
        handle_sdk_buy_item, handle_sdk_sell_item, handle_sdk_transfer,
        handle_sdk_batch_tx, handle_sdk_tx_status,
        // SDK Market
        handle_sdk_market_listings, handle_sdk_market_list,
        handle_sdk_market_delist, handle_sdk_market_offer,
        handle_sdk_market_history, handle_sdk_market_floor,
        // SDK Game
        handle_sdk_game_reward, handle_sdk_game_burn,
        handle_sdk_game_leaderboard, handle_sdk_tournament_prize,
        // SDK Auth
        handle_sdk_link_wallet, handle_sdk_session, handle_sdk_revoke,
        handle_sdk_permissions, handle_sdk_audit_log,
        // SDK Player Dashboard
        handle_sdk_player_wallets, handle_sdk_player_activity,
        // SDK Developer Dashboard
        handle_sdk_developer_dashboard,
        // SDK Shop
        handle_sdk_shop_buy, handle_sdk_shop_create_item, handle_sdk_shop_catalog,
    },
    reputation::{
        handle_reputation_status, handle_reputation_nodes, handle_reputation_node,
    },
    snapshot::{
        handle_snapshot_meta, handle_snapshot_download, handle_snapshot_create,
        handle_snapshot_state_root,
    },
    users::{handle_delete_user, handle_list_users, handle_list_users_public},
    ws::handle_websocket,
};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Health (kein Auth)
        .route("/api/v1/health", get(handle_health))
        // Öffentliche Node-Info (kein Auth, für Peer-Discovery)
        .route("/api/v1/info", get(handle_info))
        // Node-Liste für Client-Discovery (kein Auth)
        .route("/api/v1/nodes", get(handle_node_list))
        // Status & Metriken (Admin)
        .route("/api/v1/status", get(handle_status))
        .route("/api/v1/metrics", get(handle_metrics))
        .route("/api/v1/network", get(handle_network_stats))
        .route("/api/v1/chain/verify", get(handle_verify))
        // Shard-Health (Erasure Coding Monitoring)
        .route("/api/v1/shards/health", get(handle_shard_health))
        // Blöcke (Admin)
        .route("/api/v1/blocks", get(handle_list_blocks))
        .route("/api/v1/blocks/{index}", get(handle_get_block))
        // Dokumente
        .route(
            "/api/v1/documents",
            get(handle_list_documents).post(handle_upload_document),
        )
        // Suche (vor /{doc_id}, damit /search nicht als doc_id geparst wird)
        .route("/api/v1/documents/search", get(handle_search_documents))
        .route(
            "/api/v1/documents/user/{user_id}",
            get(handle_list_user_documents),
        )
        .route(
            "/api/v1/documents/{doc_id}",
            get(handle_get_document).patch(handle_patch_document),
        )
        .route(
            "/api/v1/documents/{doc_id}/delete",
            post(handle_delete_document),
        )
        .route(
            "/api/v1/documents/{doc_id}/history",
            get(handle_document_history),
        )
        .route(
            "/api/v1/documents/{doc_id}/transfer",
            post(handle_transfer_document),
        )
        .route(
            "/api/v1/documents/{doc_id}/data",
            get(handle_get_document_data),
        )
        .route(
            "/api/v1/documents/{doc_id}/download",
            get(handle_get_document_data),
        )
        // Chunk-API für Peer-Sync
        .route("/api/v1/chunk/{hash}", get(handle_get_chunk))
        // Peers (Admin)
        .route(
            "/api/v1/peers",
            get(handle_list_peers).post(handle_add_peer),
        )
        .route("/api/v1/peers/register", post(handle_register_peer))
        .route("/api/v1/peers/{idx}", delete(handle_remove_peer))
        // Sync (Admin)
        .route("/api/v1/sync", post(handle_sync))
        // P2P-Netzwerk
        .route("/api/v1/p2p/peers", get(handle_p2p_peers))
        .route("/api/v1/p2p/status", get(handle_p2p_status))
        .route("/api/v1/p2p/ping/{peer_id}", post(handle_p2p_ping))
        .route("/api/v1/p2p/dial", post(handle_p2p_dial))
        .route("/api/v1/p2p/info", get(handle_p2p_info))
        .route("/api/v1/p2p/config", get(handle_p2p_config))
        // P2P Consensus Voting (2-Phase BFT)
        .route("/api/v1/p2p/proposal", post(handle_p2p_proposal))
        .route("/api/v1/p2p/precommit", post(handle_p2p_precommit))
        // Nutzer (Admin)
        .route("/api/v1/users", get(handle_list_users))
        .route("/api/v1/users/public", get(handle_list_users_public))
        .route("/api/v1/users/{user_id}", delete(handle_delete_user))
        // Alias: Frontend ruft /api/v1/users/{id}/documents statt /api/v1/documents/user/{id}
        .route("/api/v1/users/{user_id}/documents", get(handle_list_user_documents))
        // Auth
        .route("/api/v1/auth/signup", post(handle_signup))
        .route("/api/v1/auth/login", post(handle_login))
        .route("/api/v1/auth/wallet-claim", post(handle_wallet_claim))
        // Challenge-Response Auth (Cross-Platform Login)
        .route("/api/v1/auth/challenge", post(handle_request_challenge))
        .route("/api/v1/auth/verify", post(handle_verify_challenge))
        // QR-Code Login (Cross-Device: iOS App → Website/Desktop)
        .route("/api/v1/auth/qr/create", post(handle_qr_create))
        .route("/api/v1/auth/qr/status/{token}", get(handle_qr_status))
        .route("/api/v1/auth/qr/approve", post(handle_qr_approve))
        // Admin: User-Sync zwischen Nodes
        .route("/api/v1/admin/sync-users", post(handle_sync_users))
        // PoA: Validators
        .route(
            "/api/v1/validators",
            get(handle_list_validators).post(handle_add_validator),
        )
        .route("/api/v1/validators/self", get(handle_validator_self))
        .route(
            "/api/v1/validators/{node_id}",
            delete(handle_remove_validator),
        )
        .route(
            "/api/v1/validators/{node_id}/activate",
            post(handle_set_validator_active),
        )
        // PoA: Consensus Voting
        .route("/api/v1/consensus/status", get(handle_consensus_status))
        .route("/api/v1/consensus/vote", post(handle_cast_vote))
        // Fork-Erkennung
        .route("/api/v1/forks", get(handle_detect_forks))
        .route("/api/v1/forks/resolve", post(handle_resolve_fork))
        // Finality Checkpoints
        .route("/api/v1/checkpoints", get(handle_list_checkpoints))
        .route("/api/v1/checkpoint", post(handle_receive_checkpoint))
        // Slashing
        .route("/api/v1/slashing", get(handle_slashing_info))
        .route("/api/v1/slashing/{validator_id}", get(handle_slashing_validator))
        // WebSocket
        .route("/ws", get(handle_websocket))
        // Audio-Relay für Sprachanrufe
        .route("/api/v1/call/audio/{call_id}", get(handle_audio_relay))
        // ─── Web-of-Trust ────────────────────────────────────────────────────
        // Join-Anfrage (kein Auth – neue Node meldet sich an)
        .route("/api/v1/trust/request", post(handle_trust_request))
        // Trust-Check (kein Auth – öffentlich abfragbar)
        .route("/api/v1/trust/check/{peer_id}", get(handle_trust_check))
        // Admin-Endpunkte
        .route("/api/v1/trust/pending", get(handle_trust_pending))
        .route("/api/v1/trust/registry", get(handle_trust_registry))
        .route("/api/v1/trust/approve/{peer_id}", post(handle_trust_approve))
        .route("/api/v1/trust/revoke/{peer_id}", post(handle_trust_revoke))
        .route("/api/v1/trust/history", get(handle_trust_history))
        // ─── StoneCoin Token-Economy ─────────────────────────────────────────
        .route("/api/v1/token/supply", get(handle_token_supply))
        .route("/api/v1/token/accounts", get(handle_token_accounts))
        .route("/api/v1/token/pending", get(handle_token_pending))
        .route("/api/v1/mempool/sync", get(handle_mempool_sync))
        .route("/api/v1/token/transfer", post(handle_token_transfer))
        .route("/api/v1/token/send", post(handle_token_send))
        .route("/api/v1/token/send-authenticated", post(handle_token_send_authenticated))
        .route("/api/v1/token/faucet", post(handle_token_faucet))
        .route("/api/v1/token/history/{address}", get(handle_token_history))
        .route("/api/v1/token/tx/{tx_id}", get(handle_tx_status))
        .route("/api/v1/wallet/create", post(handle_wallet_create))
        .route("/api/v1/wallet/{address}/rotations", get(handle_wallet_rotations))
        .route("/api/v1/wallet/{address}", get(handle_wallet_info))
        .route("/api/v1/wallet/{address}/balance", get(handle_wallet_balance))
        // ─── Staking Pool ────────────────────────────────────────────────────
        // SECURITY: /api/v1/token/stake und /unstake entfernt — diese Endpoints
        // akzeptierten raw TXs ohne Auth + ohne Signaturprüfung.
        // Staking nur über authentifizierte /api/v1/mining/stake|unstake.
        .route("/api/v1/staking/info", get(handle_staking_info))
        .route("/api/v1/staking/pool", get(handle_staking_pool))
        .route("/api/v1/staking/staker/{address}", get(handle_staker_info))
        // ─── Admin: Ledger & Airdrop ─────────────────────────────────────────
        .route("/api/v1/admin/ledger/rebuild", post(handle_ledger_rebuild))
        .route("/api/v1/admin/airdrop", post(handle_admin_airdrop))
        // ─── OTA Updates ─────────────────────────────────────────────────────
        .route("/api/v1/updates/status", get(handle_update_status))
        .route("/api/v1/updates/chunk/{index}", get(handle_update_chunk))
        .route("/api/v1/updates/publish", post(handle_update_publish))
        .route("/api/v1/updates/install", post(handle_update_install))
        .route("/api/v1/updates/download", post(handle_update_download))
        .route("/api/updates/download", post(handle_update_download))
        .route("/api/v1/updates/config", post(handle_update_config))
        // ─── Organisationen ──────────────────────────────────────────────────
        .route("/api/v1/orgs", get(handle_list_orgs).post(handle_create_org))
        // Aliases: Frontend ruft /orgs/list und /orgs/create statt GET/POST /orgs
        .route("/api/v1/orgs/list", get(handle_list_orgs))
        .route("/api/v1/orgs/create", post(handle_create_org))
        .route("/api/v1/orgs/invites", get(handle_my_invites))
        .route("/api/v1/orgs/invites/{invite_id}/accept", post(handle_accept_invite))
        .route("/api/v1/orgs/invites/{invite_id}/decline", post(handle_decline_invite))
        .route("/api/v1/orgs/{org_id}", get(handle_get_org))
        .route("/api/v1/orgs/{org_id}/invite", post(handle_invite))
        .route("/api/v1/orgs/{org_id}/leave", post(handle_leave_org))
        .route("/api/v1/orgs/{org_id}/members/remove", post(handle_remove_member))
        .route("/api/v1/orgs/{org_id}/members/role", post(handle_set_role))
        .route("/api/v1/orgs/{org_id}/channels", post(handle_create_channel))
        .route("/api/v1/orgs/{org_id}/chat", post(handle_send_message))
        .route("/api/v1/orgs/{org_id}/chat/{channel_id}", get(handle_get_chat))
        // ─── Globaler Chat ───────────────────────────────────────────────────
        .route("/api/v1/chat/send", post(handle_chat_send))
        .route("/api/v1/chat/conversations", get(handle_chat_conversations))
        .route("/api/v1/chat/messages/{peer_wallet}", get(handle_chat_messages))
        .route("/api/v1/chat/pending", get(handle_chat_pending))
        .route("/api/v1/chat/proof/{msg_id}", get(handle_chat_proof))
        .route("/api/v1/chat/resolve/{identifier}", get(handle_chat_resolve))
        // Öffentlicher Resolve – für Peer-to-Peer User-Suche (kein Auth nötig)
        .route("/api/v1/chat/resolve-public/{identifier}", get(handle_chat_resolve_public))
        // ─── Chat Kontakte (Adding) ─────────────────────────────────
        .route("/api/v1/chat/contacts", get(handle_list_contacts).post(handle_add_contact))
        .route("/api/v1/chat/contacts/{wallet}", delete(handle_remove_contact))
        // ─── Kontaktanfragen (Friend Request System) ────────────────
        .route("/api/v1/chat/contacts/request", post(handle_send_contact_request))
        .route("/api/v1/chat/contacts/requests", get(handle_list_contact_requests))
        .route("/api/v1/chat/contacts/requests/{id}/accept", post(handle_accept_contact_request))
        .route("/api/v1/chat/contacts/requests/{id}/decline", post(handle_decline_contact_request))
        // ─── Stonecoins im Chat senden & anfragen ───────────────────
        .route("/api/v1/chat/send-coins", post(handle_chat_send_coins))
        .route("/api/v1/chat/request-coins", post(handle_chat_request_coins))
        // ─── Gruppenchats ────────────────────────────────────────────────────
        .route("/api/v1/chat/groups", get(handle_list_groups).post(handle_create_group))
        .route("/api/v1/chat/groups/{group_id}", get(handle_get_group))
        .route("/api/v1/chat/groups/{group_id}/send", post(handle_group_send))
        .route("/api/v1/chat/groups/{group_id}/messages", get(handle_group_messages))
        .route("/api/v1/chat/groups/{group_id}/members", post(handle_add_group_member))
        .route("/api/v1/chat/groups/{group_id}/members/{wallet}", delete(handle_remove_group_member))
        // ─── WebRTC Call-Signaling ───────────────────────────────────────────
        .route("/api/v1/call/signal", post(handle_send_signal))
        .route("/api/v1/call/signal/{peer_wallet}", get(handle_get_signals))
        // ─── Chat Policy (Self-Destruct, Reports, Stake-Gate) ──────────────
        .route("/api/v1/chat/policy/status", get(handle_chat_policy_status))
        .route("/api/v1/chat/policy/message/{msg_id}", get(handle_chat_policy_message))
        .route("/api/v1/chat/report", post(handle_chat_report))
        .route("/api/v1/chat/reports", get(handle_chat_reports))
        .route("/api/v1/chat/report/{report_id}/vote", post(handle_chat_report_vote))
        // ─── Mining Dashboard ───────────────────────────────────────────────
        .route("/api/v1/mining/status", get(handle_mining_status))
        .route("/api/v1/mining/throttle", post(handle_mining_throttle))
        .route("/api/v1/mining/withdraw", post(handle_mining_withdraw))
        .route("/api/v1/mining/stake", post(handle_mining_stake))
        .route("/api/v1/mining/unstake", post(handle_mining_unstake))
        .route("/api/v1/mining/bind-wallet", post(handle_bind_mining_wallet))
        .route("/api/v1/mining/wallet", get(handle_mining_wallet_info))
        // ─── Competitive PoW: External Miner API ────────────────────────
        .route("/api/v1/mining/template", get(handle_mining_template))
        .route("/api/v1/mining/submit", post(handle_mining_submit))
        // ─── Miner Status Relay (Bootstrap-Server als Relay) ────────────
        .route("/api/v1/mining/report", post(handle_mining_report))
        .route("/api/v1/mining/remote-status/{wallet}", get(handle_mining_remote_status))
        // ─── Reputation ──────────────────────────────────────────────────────
        .route("/api/v1/reputation/status", get(handle_reputation_status))
        .route("/api/v1/reputation/nodes", get(handle_reputation_nodes))
        .route("/api/v1/reputation/node/{node_id}", get(handle_reputation_node))
        // ─── Snapshots (Fast Sync) ──────────────────────────────────────────
        .route("/api/v1/snapshot/meta", get(handle_snapshot_meta))
        .route("/api/v1/snapshot/download", get(handle_snapshot_download))
        .route("/api/v1/snapshot/create", post(handle_snapshot_create))
        .route("/api/v1/snapshot/state_root", get(handle_snapshot_state_root))
        // ─── SDK ────────────────────────────────────────────────────────────
        // Developer
        .route("/api/v1/sdk/register", post(handle_sdk_register))
        .route("/api/v1/sdk/quick-register", post(handle_sdk_quick_register))
        .route("/api/v1/sdk/game/{game_id}", get(handle_sdk_game_info))
        .route("/api/v1/sdk/game/{game_id}/status", post(handle_sdk_game_status))
        // Consent
        .route("/api/v1/sdk/consent/request", post(handle_sdk_consent_request))
        .route("/api/v1/sdk/consent/pending", get(handle_sdk_consent_pending))
        .route("/api/v1/sdk/consent/approve", post(handle_sdk_consent_approve))
        .route("/api/v1/sdk/consent/reject", post(handle_sdk_consent_reject))
        // Wallet
        .route("/api/v1/sdk/wallet/create", post(handle_sdk_wallet_create))
        .route("/api/v1/sdk/wallet/link", post(handle_sdk_wallet_link))
        .route("/api/v1/sdk/wallet/balance", get(handle_sdk_wallet_balance))
        .route("/api/v1/sdk/wallet/transactions", get(handle_sdk_wallet_transactions))
        .route("/api/v1/sdk/wallet/send", post(handle_sdk_wallet_send))
        .route("/api/v1/sdk/wallet/withdraw", post(handle_sdk_wallet_withdraw))
        .route("/api/v1/sdk/wallet/nft-inventory", get(handle_sdk_nft_inventory))
        .route("/api/v1/sdk/wallet/freeze", post(handle_sdk_wallet_freeze))
        .route("/api/v1/sdk/wallet/unfreeze", post(handle_sdk_wallet_unfreeze))
        .route("/api/v1/sdk/wallet/set-limit", post(handle_sdk_wallet_set_limit))
        // TX
        .route("/api/v1/sdk/tx/buy-item", post(handle_sdk_buy_item))
        .route("/api/v1/sdk/tx/sell-item", post(handle_sdk_sell_item))
        .route("/api/v1/sdk/tx/transfer", post(handle_sdk_transfer))
        .route("/api/v1/sdk/tx/batch", post(handle_sdk_batch_tx))
        .route("/api/v1/sdk/tx/status/{tx_id}", get(handle_sdk_tx_status))
        // Market
        .route("/api/v1/sdk/market/listings", get(handle_sdk_market_listings))
        .route("/api/v1/sdk/market/list", post(handle_sdk_market_list))
        .route("/api/v1/sdk/market/delist", post(handle_sdk_market_delist))
        .route("/api/v1/sdk/market/offer", post(handle_sdk_market_offer))
        .route("/api/v1/sdk/market/history/{item_id}", get(handle_sdk_market_history))
        .route("/api/v1/sdk/market/floor/{category}", get(handle_sdk_market_floor))
        // Game
        .route("/api/v1/sdk/game/reward", post(handle_sdk_game_reward))
        .route("/api/v1/sdk/game/burn", post(handle_sdk_game_burn))
        .route("/api/v1/sdk/game/leaderboard", get(handle_sdk_game_leaderboard))
        .route("/api/v1/sdk/game/tournament/prize", post(handle_sdk_tournament_prize))
        // Auth
        .route("/api/v1/sdk/auth/link-wallet", post(handle_sdk_link_wallet))
        .route("/api/v1/sdk/auth/session", post(handle_sdk_session))
        .route("/api/v1/sdk/auth/revoke", post(handle_sdk_revoke))
        .route("/api/v1/sdk/auth/permissions", get(handle_sdk_permissions))
        .route("/api/v1/sdk/auth/audit-log", get(handle_sdk_audit_log))
        // Player Dashboard
        .route("/api/v1/sdk/player/wallets", get(handle_sdk_player_wallets))
        .route("/api/v1/sdk/player/activity", get(handle_sdk_player_activity))
        // Developer Dashboard
        .route("/api/v1/sdk/developer/dashboard", get(handle_sdk_developer_dashboard))
        // In-Game Shop
        .route("/api/v1/sdk/shop/catalog", get(handle_sdk_shop_catalog))
        .route("/api/v1/sdk/shop/item", post(handle_sdk_shop_create_item))
        .route("/api/v1/sdk/shop/buy", post(handle_sdk_shop_buy))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
        .layer(build_cors())
        .with_state(state)
}

pub fn build_cors() -> CorsLayer {
    let allowed_origins: Vec<axum::http::HeaderValue> =
        std::env::var("STONE_CORS_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|s| s.trim().parse().ok())
            .collect();

    if allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(allowed_origins))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
    }
}
