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
    auth::{handle_login, handle_signup, handle_sync_users, handle_wallet_claim},
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
    },
    chat::{
        handle_chat_conversations, handle_chat_messages, handle_chat_pending,
        handle_chat_resolve, handle_chat_send,
    },
    chat_policy::{
        handle_chat_policy_status, handle_chat_policy_message,
        handle_chat_report, handle_chat_reports, handle_chat_report_vote,
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
    peers::{handle_add_peer, handle_list_peers, handle_remove_peer, handle_sync},
    poa::{
        handle_add_validator, handle_cast_vote, handle_consensus_status,
        handle_detect_forks, handle_list_checkpoints, handle_list_validators,
        handle_receive_checkpoint, handle_remove_validator,
        handle_resolve_fork, handle_set_validator_active, handle_slashing_info,
        handle_slashing_validator, handle_validator_self,
    },
    status::{handle_health, handle_info, handle_metrics, handle_network_stats, handle_shard_health, handle_status, handle_verify},
    token::{
        handle_token_accounts, handle_token_faucet, handle_token_history,
        handle_token_pending, handle_token_send, handle_token_send_authenticated,
        handle_token_supply,
        handle_token_transfer, handle_wallet_balance, handle_wallet_create,
        handle_wallet_info, handle_wallet_rotations,
        handle_token_stake, handle_token_unstake,
        handle_staking_info, handle_staking_pool, handle_staker_info,
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
    reputation::{
        handle_reputation_status, handle_reputation_nodes, handle_reputation_node,
    },
    users::{handle_delete_user, handle_list_users},
    ws::handle_websocket,
};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Health (kein Auth)
        .route("/api/v1/health", get(handle_health))
        // Öffentliche Node-Info (kein Auth, für Peer-Discovery)
        .route("/api/v1/info", get(handle_info))
        // Status & Metriken (Admin)
        .route("/api/v1/status", get(handle_status))
        .route("/api/v1/metrics", get(handle_metrics))
        .route("/api/v1/network", get(handle_network_stats))
        .route("/api/v1/chain/verify", get(handle_verify))
        // Shard-Health (Erasure Coding Monitoring)
        .route("/api/v1/shards/health", get(handle_shard_health))
        // Blöcke (Admin)
        .route("/api/v1/blocks", get(handle_list_blocks))
        .route("/api/v1/blocks/:index", get(handle_get_block))
        // Dokumente
        .route(
            "/api/v1/documents",
            get(handle_list_documents).post(handle_upload_document),
        )
        // Suche (vor /:doc_id, damit /search nicht als doc_id geparst wird)
        .route("/api/v1/documents/search", get(handle_search_documents))
        .route(
            "/api/v1/documents/user/:user_id",
            get(handle_list_user_documents),
        )
        .route(
            "/api/v1/documents/:doc_id",
            get(handle_get_document).patch(handle_patch_document),
        )
        .route(
            "/api/v1/documents/:doc_id/delete",
            post(handle_delete_document),
        )
        .route(
            "/api/v1/documents/:doc_id/history",
            get(handle_document_history),
        )
        .route(
            "/api/v1/documents/:doc_id/transfer",
            post(handle_transfer_document),
        )
        .route(
            "/api/v1/documents/:doc_id/data",
            get(handle_get_document_data),
        )
        .route(
            "/api/v1/documents/:doc_id/download",
            get(handle_get_document_data),
        )
        // Chunk-API für Peer-Sync
        .route("/api/v1/chunk/:hash", get(handle_get_chunk))
        // Peers (Admin)
        .route(
            "/api/v1/peers",
            get(handle_list_peers).post(handle_add_peer),
        )
        .route("/api/v1/peers/:idx", delete(handle_remove_peer))
        // Sync (Admin)
        .route("/api/v1/sync", post(handle_sync))
        // P2P-Netzwerk
        .route("/api/v1/p2p/peers", get(handle_p2p_peers))
        .route("/api/v1/p2p/status", get(handle_p2p_status))
        .route("/api/v1/p2p/ping/:peer_id", post(handle_p2p_ping))
        .route("/api/v1/p2p/dial", post(handle_p2p_dial))
        .route("/api/v1/p2p/info", get(handle_p2p_info))
        .route("/api/v1/p2p/config", get(handle_p2p_config))
        // P2P Consensus Voting (2-Phase BFT)
        .route("/api/v1/p2p/proposal", post(handle_p2p_proposal))
        .route("/api/v1/p2p/precommit", post(handle_p2p_precommit))
        // Nutzer (Admin)
        .route("/api/v1/users", get(handle_list_users))
        .route("/api/v1/users/:user_id", delete(handle_delete_user))
        // Auth
        .route("/api/v1/auth/signup", post(handle_signup))
        .route("/api/v1/auth/login", post(handle_login))
        .route("/api/v1/auth/wallet-claim", post(handle_wallet_claim))
        // Admin: User-Sync zwischen Nodes
        .route("/api/v1/admin/sync-users", post(handle_sync_users))
        // PoA: Validators
        .route(
            "/api/v1/validators",
            get(handle_list_validators).post(handle_add_validator),
        )
        .route("/api/v1/validators/self", get(handle_validator_self))
        .route(
            "/api/v1/validators/:node_id",
            delete(handle_remove_validator),
        )
        .route(
            "/api/v1/validators/:node_id/activate",
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
        .route("/api/v1/slashing/:validator_id", get(handle_slashing_validator))
        // WebSocket
        .route("/ws", get(handle_websocket))
        // ─── Web-of-Trust ────────────────────────────────────────────────────
        // Join-Anfrage (kein Auth – neue Node meldet sich an)
        .route("/api/v1/trust/request", post(handle_trust_request))
        // Trust-Check (kein Auth – öffentlich abfragbar)
        .route("/api/v1/trust/check/:peer_id", get(handle_trust_check))
        // Admin-Endpunkte
        .route("/api/v1/trust/pending", get(handle_trust_pending))
        .route("/api/v1/trust/registry", get(handle_trust_registry))
        .route("/api/v1/trust/approve/:peer_id", post(handle_trust_approve))
        .route("/api/v1/trust/revoke/:peer_id", post(handle_trust_revoke))
        .route("/api/v1/trust/history", get(handle_trust_history))
        // ─── StoneCoin Token-Economy ─────────────────────────────────────────
        .route("/api/v1/token/supply", get(handle_token_supply))
        .route("/api/v1/token/accounts", get(handle_token_accounts))
        .route("/api/v1/token/pending", get(handle_token_pending))
        .route("/api/v1/token/transfer", post(handle_token_transfer))
        .route("/api/v1/token/send", post(handle_token_send))
        .route("/api/v1/token/send-authenticated", post(handle_token_send_authenticated))
        .route("/api/v1/token/faucet", post(handle_token_faucet))
        .route("/api/v1/token/history/:address", get(handle_token_history))
        .route("/api/v1/wallet/create", post(handle_wallet_create))
        .route("/api/v1/wallet/:address/rotations", get(handle_wallet_rotations))
        .route("/api/v1/wallet/:address", get(handle_wallet_info))
        .route("/api/v1/wallet/:address/balance", get(handle_wallet_balance))
        // ─── Staking Pool ────────────────────────────────────────────────────
        .route("/api/v1/token/stake", post(handle_token_stake))
        .route("/api/v1/token/unstake", post(handle_token_unstake))
        .route("/api/v1/staking/info", get(handle_staking_info))
        .route("/api/v1/staking/pool", get(handle_staking_pool))
        .route("/api/v1/staking/staker/:address", get(handle_staker_info))
        // ─── OTA Updates ─────────────────────────────────────────────────────
        .route("/api/v1/updates/status", get(handle_update_status))
        .route("/api/v1/updates/chunk/:index", get(handle_update_chunk))
        .route("/api/v1/updates/publish", post(handle_update_publish))
        .route("/api/v1/updates/install", post(handle_update_install))
        .route("/api/v1/updates/download", post(handle_update_download))
        .route("/api/updates/download", post(handle_update_download))
        .route("/api/v1/updates/config", post(handle_update_config))
        // ─── Organisationen ──────────────────────────────────────────────────
        .route("/api/v1/orgs", get(handle_list_orgs).post(handle_create_org))
        .route("/api/v1/orgs/invites", get(handle_my_invites))
        .route("/api/v1/orgs/invites/:invite_id/accept", post(handle_accept_invite))
        .route("/api/v1/orgs/invites/:invite_id/decline", post(handle_decline_invite))
        .route("/api/v1/orgs/:org_id", get(handle_get_org))
        .route("/api/v1/orgs/:org_id/invite", post(handle_invite))
        .route("/api/v1/orgs/:org_id/leave", post(handle_leave_org))
        .route("/api/v1/orgs/:org_id/members/remove", post(handle_remove_member))
        .route("/api/v1/orgs/:org_id/members/role", post(handle_set_role))
        .route("/api/v1/orgs/:org_id/channels", post(handle_create_channel))
        .route("/api/v1/orgs/:org_id/chat", post(handle_send_message))
        .route("/api/v1/orgs/:org_id/chat/:channel_id", get(handle_get_chat))
        // ─── Globaler Chat ───────────────────────────────────────────────────
        .route("/api/v1/chat/send", post(handle_chat_send))
        .route("/api/v1/chat/conversations", get(handle_chat_conversations))
        .route("/api/v1/chat/messages/:peer_wallet", get(handle_chat_messages))
        .route("/api/v1/chat/pending", get(handle_chat_pending))
        .route("/api/v1/chat/resolve/:identifier", get(handle_chat_resolve))
        // ─── Chat Policy (Self-Destruct, Reports, Stake-Gate) ──────────────
        .route("/api/v1/chat/policy/status", get(handle_chat_policy_status))
        .route("/api/v1/chat/policy/message/:msg_id", get(handle_chat_policy_message))
        .route("/api/v1/chat/report", post(handle_chat_report))
        .route("/api/v1/chat/reports", get(handle_chat_reports))
        .route("/api/v1/chat/report/:report_id/vote", post(handle_chat_report_vote))
        // ─── Mining Dashboard ───────────────────────────────────────────────
        .route("/api/v1/mining/status", get(handle_mining_status))
        .route("/api/v1/mining/throttle", post(handle_mining_throttle))
        .route("/api/v1/mining/withdraw", post(handle_mining_withdraw))
        .route("/api/v1/mining/stake", post(handle_mining_stake))
        .route("/api/v1/mining/unstake", post(handle_mining_unstake))
        // ─── Reputation ──────────────────────────────────────────────────────
        .route("/api/v1/reputation/status", get(handle_reputation_status))
        .route("/api/v1/reputation/nodes", get(handle_reputation_nodes))
        .route("/api/v1/reputation/node/:node_id", get(handle_reputation_node))
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
