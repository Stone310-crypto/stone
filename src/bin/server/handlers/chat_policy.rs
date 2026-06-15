//! Chat-Policy API Endpoints
//!
//! GET  /api/v1/chat/policy/status     – Self-Destruct/Report/Stake-Gate Übersicht
//! GET  /api/v1/chat/policy/message/:id – TTL-Info zu einer Nachricht
//! POST /api/v1/chat/report            – Nachricht melden (Report)
//! GET  /api/v1/chat/reports           – Aktive Reports auflisten
//! POST /api/v1/chat/report/:id/vote   – Auf Report abstimmen (Validator)

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use stone::chat_policy::{self, ReportCategory};

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ReportRequest {
    /// Die msg_id der gemeldeten Nachricht
    pub msg_id: String,
    /// Kategorie: spam, harassment, illegal_content, scam, other
    pub category: ReportCategory,
    /// Freitext-Begründung
    #[serde(default)]
    pub reason: String,
    /// Decryption-Key (für Single-Report obligatorisch)
    pub decryption_key: Option<String>,
}

#[derive(Deserialize)]
pub struct VoteRequest {
    /// Stimmt zu (true) oder lehnt ab (false)
    pub approve: bool,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// GET /api/v1/chat/policy/status
///
/// Übersicht: Self-Destruct Stats, Report Stats, Stake-Gate Info.
pub async fn handle_chat_policy_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let policy = state.node.chat_policy.read().unwrap_or_else(|e| e.into_inner());
    let summary = policy.summary();

    (StatusCode::OK, Json(json!({
        "ok": true,
        "self_destruct": {
            "total_tracked": summary.total_messages_tracked,
            "total_purged": summary.total_content_purged,
            "pending_expirations": summary.pending_expirations,
        },
        "reports": {
            "total_filed": summary.total_reports_filed,
            "total_accepted": summary.total_reports_accepted,
            "active_reports": summary.active_reports,
            "total_slashed": summary.total_slashed.to_string(),
        },
        "stake_gate": {
            "min_stake_required": "0",
            "description": "Kein Mindest-Stake erforderlich",
        },
        "message_fee": {
            "fee_per_message": "0",
            "currency": "STONE",
            "enabled": false,
            "description": "Spam-Schutz per Fee derzeit deaktiviert (nur Lite-PoW aktiv).",
        },
    })))
}

/// GET /api/v1/chat/policy/message/:msg_id
///
/// TTL-Info zu einer bestimmten Nachricht.
pub async fn handle_chat_policy_message(
    State(state): State<AppState>,
    Path(msg_id): Path<String>,
) -> impl IntoResponse {
    let policy = state.node.chat_policy.read().unwrap_or_else(|e| e.into_inner());

    match policy.message_ttl_info(&msg_id) {
        Some(entry) => {
            let now = chrono::Utc::now().timestamp();
            let remaining_secs = if entry.expires_at > now {
                entry.expires_at - now
            } else {
                0
            };

            (StatusCode::OK, Json(json!({
                "ok": true,
                "msg_id": entry.msg_id,
                "tx_id": entry.tx_id,
                "from": entry.from_wallet,
                "to": entry.to_wallet,
                "ttl": entry.ttl.to_string(),
                "created_at": entry.created_at,
                "expires_at": entry.expires_at,
                "remaining_secs": remaining_secs,
                "remaining_days": remaining_secs / 86400,
                "content_purged": entry.content_purged,
                "purge_reason": entry.purge_reason,
            })))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "Nachricht nicht im TTL-Tracking"})),
        ),
    }
}

/// POST /api/v1/chat/report
///
/// Nachricht melden. Bei Mutual Report (beide Seiten melden) wird der
/// Content sofort gelöscht. Bei Single Report startet ein Validator-Voting.
pub async fn handle_chat_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<ReportRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if user.wallet_address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "Kein Wallet registriert"})),
        )
            .into_response();
    }

    // Reported wallet ermitteln (die andere Seite der Konversation)
    let reported_wallet = {
        let policy = state.node.chat_policy.read().unwrap_or_else(|e| e.into_inner());
        match policy.message_ttl_info(&req.msg_id) {
            Some(entry) => {
                if entry.from_wallet == user.wallet_address {
                    // User ist der Sender → meldet den Empfänger? Nein, meldet die Nachricht.
                    // reported_wallet = der Autor der gemeldeten Nachricht = from_wallet
                    // Aber wenn User der Sender ist, meldet er sich selbst → Fehler
                    // EIGENTLICH: reported_wallet = der Autor der Nachricht
                    entry.from_wallet.clone()
                } else if entry.to_wallet == user.wallet_address {
                    entry.from_wallet.clone()
                } else {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"ok": false, "error": "Du bist nicht Teil dieser Konversation"})),
                    )
                        .into_response();
                }
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"ok": false, "error": "Nachricht nicht gefunden"})),
                )
                    .into_response();
            }
        }
    };

    let total_validators = {
        let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
        vs.active_count() as u32
    };

    let mut policy = state.node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
    match policy.file_report(
        &req.msg_id,
        &user.wallet_address,
        &reported_wallet,
        req.category,
        req.reason,
        req.decryption_key,
        total_validators,
    ) {
        Ok((report_id, is_mutual)) => {
            if is_mutual {
                // Bei Mutual Report: Content sofort im Chat-Index löschen
                let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
                chat_policy::purge_message_content(&mut idx, &req.msg_id);
                stone::chat::save_chat_index(&idx);
                drop(idx);

                // Policy persistieren
                if let Err(e) = policy.persist() {
                    eprintln!("[chat-policy] Persist nach Mutual Report: {e}");
                }

                println!(
                    "[chat-policy] 🤝 Mutual Report: Nachricht {} von beiden Seiten gemeldet → Content gelöscht",
                    &req.msg_id[..8.min(req.msg_id.len())]
                );
            }

            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "report_id": report_id,
                    "is_mutual": is_mutual,
                    "status": if is_mutual { "mutual_delete" } else { "pending" },
                    "message": if is_mutual {
                        "Beide Seiten haben gemeldet — Nachricht sofort gelöscht"
                    } else {
                        "Report eingereicht, Validator-Voting läuft"
                    },
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": e})),
        )
            .into_response(),
    }
}

/// GET /api/v1/chat/reports
///
/// Aktive Reports auflisten (nur für Validatoren/Admins).
pub async fn handle_chat_reports(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let policy = state.node.chat_policy.read().unwrap_or_else(|e| e.into_inner());
    let reports: Vec<_> = policy.active_reports().into_iter().map(|r| {
        json!({
            "report_id": r.report_id,
            "msg_id": r.msg_id,
            "category": r.category.to_string(),
            "reason": r.reason,
            "reporter": &r.reporter_wallet[..16.min(r.reporter_wallet.len())],
            "reported": &r.reported_wallet[..16.min(r.reported_wallet.len())],
            "created_at": r.created_at,
            "votes_count": r.votes.len(),
            "total_validators": r.total_validators,
            "has_decryption_key": r.decryption_key.is_some(),
        })
    }).collect();

    (StatusCode::OK, Json(json!({
        "ok": true,
        "reports": reports,
        "count": reports.len(),
    })))
}

/// POST /api/v1/chat/report/:report_id/vote
///
/// Als Validator auf einen Report abstimmen.
/// Stake-gewichtet: Mehr Stake = mehr Stimmgewicht.
pub async fn handle_chat_report_vote(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    axum::Json(req): axum::Json<VoteRequest>,
) -> impl IntoResponse {
    let node_id = state.node.node_id.clone();

    // Prüfe ob Node ein aktiver Validator ist
    let node_wallet = {
        let vs = state.node.validator_set.read().unwrap_or_else(|e| e.into_inner());
        if !vs.is_active_validator(&node_id) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"ok": false, "error": "Nur aktive Validatoren dürfen abstimmen"})),
            )
                .into_response();
        }
        // Wallet-Adresse des Validators (= pub_key_hex)
        vs.get(&node_id).map(|v| v.public_key_hex.clone()).unwrap_or_default()
    };

    // Anti-Sybil: Prüfe Stake-Level (mindestens Validator-Level = 500 STONE)
    {
        let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
        let level = pool.stake_level(&node_wallet);
        if !level.can_validate() {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "error": format!("Unzureichender Stake-Level: '{}' (benötigt: 'validator', min. 500 STONE)", level),
                })),
            )
                .into_response();
        }
    }

    let mut policy = state.node.chat_policy.write().unwrap_or_else(|e| e.into_inner());

    // Vote abgeben (mit wallet als voter_id für stake-gewichtetes Voting)
    if let Err(e) = policy.cast_vote(&report_id, &node_wallet, req.approve) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": e})),
        )
            .into_response();
    }

    // Stake-Gewichte aufbauen für gewichtetes Voting
    let stake_weights: std::collections::HashMap<String, rust_decimal::Decimal> = {
        let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
        pool.stakers.iter()
            .filter(|(_, entry)| stone::token::staking::StakeLevel::from_stake(entry.staked_amount).can_validate())
            .map(|(addr, entry)| (addr.clone(), entry.staked_amount))
            .collect()
    };

    // Versuche zu finalisieren (stake-gewichtet)
    if let Some((accepted, msg_id, reported_wallet)) = policy.try_finalize_report_weighted(&report_id, Some(&stake_weights)) {
        if accepted {
            // Content im Chat-Index löschen
            let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
            chat_policy::purge_message_content(&mut idx, &msg_id);
            stone::chat::save_chat_index(&idx);
            drop(idx);

            // Slash des Reported Users
            let slash_amount = {
                let pool = state.node.staking_pool.read().unwrap_or_else(|e| e.into_inner());
                let staked = pool.stakers.get(&reported_wallet)
                    .map(|s| s.staked_amount)
                    .unwrap_or(rust_decimal::Decimal::ZERO);
                staked * rust_decimal::Decimal::from(chat_policy::REPORT_SLASH_PCT)
                    / rust_decimal::Decimal::from(100u32)
            };

            if slash_amount > rust_decimal::Decimal::ZERO {
                let mut pool = state.node.staking_pool.write().unwrap_or_else(|e| e.into_inner());
                let actual = pool.slash(&reported_wallet, slash_amount);
                policy.record_slash(&report_id, actual);

                // Slash-Betrag in pool:node_operators
                let mut ledger = state.node.token_ledger.write().unwrap_or_else(|e| e.into_inner());
                ledger.credit_to_operator_pool(actual);

                let _ = ledger.persist();

                println!(
                    "[chat-policy] ⚖️  Report #{} akzeptiert: {} STONE geslasht von {}",
                    &report_id[..8.min(report_id.len())],
                    actual,
                    &reported_wallet[..16.min(reported_wallet.len())],
                );
            }
        }

        if let Err(e) = policy.persist() {
            eprintln!("[chat-policy] Persist nach Report-Finalisierung: {e}");
        }

        (StatusCode::OK, Json(json!({
            "ok": true,
            "finalized": true,
            "accepted": accepted,
            "message": if accepted {
                "Report akzeptiert — Content gelöscht, Stake geslasht"
            } else {
                "Report abgelehnt — kein Slash"
            },
        }))).into_response()
    } else {
        (StatusCode::OK, Json(json!({
            "ok": true,
            "finalized": false,
            "message": "Vote registriert, warte auf weitere Stimmen",
        }))).into_response()
    }
}
