//! User management handlers.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::auth::save_users;

use super::super::auth_middleware::{require_admin, require_user};
use super::super::state::AppState;

#[derive(Deserialize)]
pub struct UserQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default)]
    pub per_page: Option<usize>,
}

/// GET /api/v1/users – Alle Nutzer mit Quota-Info (Admin)
pub async fn handle_list_users(
    headers: HeaderMap,
    Query(q): Query<UserQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let users = state.users.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let chain = state.node.chain.lock().unwrap_or_else(|e| e.into_inner());

    let search = q.q.as_deref().unwrap_or("").to_lowercase();
    let per_page = q.per_page.unwrap_or(50).min(500);
    let page = q.page.unwrap_or(0);

    let mut result: Vec<serde_json::Value> = users
        .iter()
        .filter(|u| {
            if search.is_empty() {
                return true;
            }
            u.name.to_lowercase().contains(&search) || u.id.to_lowercase().contains(&search)
        })
        .map(|u| {
            let used = chain.user_usage_bytes(&u.id);
            json!({
                "id": u.id,
                "name": u.name,
                "quota_bytes": u.quota_bytes,
                "used_bytes": used,
                "quota_pct": if u.quota_bytes == 0 || u.quota_bytes == u64::MAX { 0.0 } else {
                    used as f64 / u.quota_bytes as f64 * 100.0
                },
                "document_count": chain.list_documents_for_user(&u.id).len(),
            })
        })
        .collect();

    result.sort_by(|a, b| {
        let da = a["document_count"].as_u64().unwrap_or(0);
        let db = b["document_count"].as_u64().unwrap_or(0);
        db.cmp(&da)
    });

    let total = result.len();
    let paginated: Vec<_> = result
        .into_iter()
        .skip(page * per_page)
        .take(per_page)
        .collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "users": paginated,
        })),
    ))
}

/// GET /api/v1/users/public – Öffentliche User-Liste (Name, ID, Wallet).
/// Kein Auth nötig – für Peer-to-Peer User-Sync zwischen Nodes mit
/// unterschiedlichen Admin-Keys.
pub async fn handle_list_users_public(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let users = state.users.lock().unwrap_or_else(|e| e.into_inner());

    let list: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            json!({
                "id": u.id,
                "name": u.name,
                "wallet_address": u.wallet_address,
            })
        })
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "total": list.len(),
            "users": list,
        })),
    )
}

/// DELETE /api/v1/users/:user_id – Nutzer löschen (Admin)
pub async fn handle_delete_user(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if user_id == "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Konto kann nicht gelöscht werden"})),
        )
            .into_response());
    }

    // Wallet-Adresse VOR dem Loeschen ermitteln (fuer DSGVO-Purge)
    let wallet_address = {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        users.iter().find(|u| u.id == user_id).map(|u| u.wallet_address.clone())
    };

    let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
    let before = users.len();
    users.retain(|u| u.id != user_id);
    if users.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Nutzer nicht gefunden"})),
        )
            .into_response());
    }
    save_users(&users);
    drop(users);

    // ── DSGVO Art. 17: Chat-Content, Gruppen, Kontakte purgen ──────────
    let mut dm_purged = 0u32;
    let mut group_purged = 0u32;
    let mut contacts_removed = false;

    if let Some(ref wallet) = wallet_address {
        if !wallet.is_empty() {
            // 1) DM-Nachrichten purgen
            {
                let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
                dm_purged = stone::chat::gdpr_purge_wallet(&mut idx, wallet);
                stone::chat::save_chat_index(&idx);
            }

            // 2) Gruppen-Nachrichten purgen + Mitgliedschaft entfernen
            {
                let mut groups = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
                group_purged = stone::chat::gdpr_purge_wallet_groups(&mut groups, wallet);
                stone::chat::save_chat_groups(&groups);
            }

            // 3) Kontakte und Kontaktanfragen entfernen
            {
                let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
                let mut requests = state.contact_requests.lock().unwrap_or_else(|e| e.into_inner());
                stone::chat::gdpr_purge_wallet_contacts(&mut contacts, &mut requests, wallet);
                stone::chat::save_contacts(&contacts);
                stone::chat::save_contact_requests(&requests);
                contacts_removed = true;
            }

            // 4) DSGVO-Loeschung im ChatPolicyStore protokollieren
            {
                let mut policy = state.node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
                policy.record_gdpr_deletion(stone::chat_policy::GdprDeletionRecord {
                    wallet: wallet.clone(),
                    deleted_at: chrono::Utc::now().timestamp(),
                    messages_purged: dm_purged,
                    group_messages_purged: group_purged,
                    contacts_removed,
                });
                let _ = policy.persist();
            }

            println!(
                "[gdpr] Art.17 komplett: User {} (Wallet {}) — {} DM + {} Gruppen geloescht",
                user_id,
                &wallet[..12.min(wallet.len())],
                dm_purged,
                group_purged,
            );
        }
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "message": format!("Nutzer {user_id} gelöscht"),
            "gdpr": {
                "wallet": wallet_address.unwrap_or_default(),
                "messages_purged": dm_purged,
                "group_messages_purged": group_purged,
                "contacts_removed": contacts_removed,
            }
        })),
    ))
}

/// DELETE /api/v1/account — Eigenen Account loeschen (Self-Service, DSGVO Art. 17).
///
/// Authentifiziert ueber Session-Token. Loescht den eigenen User-Account
/// und fuehrt den vollstaendigen DSGVO-Purge durch (Chat, Gruppen, Kontakte).
pub async fn handle_delete_own_account(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state).map_err(|e| e)?;
    let user_id = user.id.clone();
    let wallet = user.wallet_address.clone();

    if user_id == "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Konto kann nicht gelöscht werden"})),
        )
            .into_response());
    }

    // User aus der Datenbank entfernen
    {
        let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        let before = users.len();
        users.retain(|u| u.id != user_id);
        if users.len() == before {
            return Err((
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Nutzer nicht gefunden"})),
            )
                .into_response());
        }
        save_users(&users);
    }

    // ── DSGVO Art. 17: Chat-Content, Gruppen, Kontakte purgen ──────────
    let mut dm_purged = 0u32;
    let mut group_purged = 0u32;
    let mut contacts_removed = false;

    if !wallet.is_empty() {
        {
            let mut idx = state.chat_index.lock().unwrap_or_else(|e| e.into_inner());
            dm_purged = stone::chat::gdpr_purge_wallet(&mut idx, &wallet);
            stone::chat::save_chat_index(&idx);
        }
        {
            let mut groups = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
            group_purged = stone::chat::gdpr_purge_wallet_groups(&mut groups, &wallet);
            stone::chat::save_chat_groups(&groups);
        }
        {
            let mut contacts = state.contacts.lock().unwrap_or_else(|e| e.into_inner());
            let mut requests = state.contact_requests.lock().unwrap_or_else(|e| e.into_inner());
            stone::chat::gdpr_purge_wallet_contacts(&mut contacts, &mut requests, &wallet);
            stone::chat::save_contacts(&contacts);
            stone::chat::save_contact_requests(&requests);
            contacts_removed = true;
        }
        {
            let mut policy = state.node.chat_policy.write().unwrap_or_else(|e| e.into_inner());
            policy.record_gdpr_deletion(stone::chat_policy::GdprDeletionRecord {
                wallet: wallet.clone(),
                deleted_at: chrono::Utc::now().timestamp(),
                messages_purged: dm_purged,
                group_messages_purged: group_purged,
                contacts_removed,
            });
            let _ = policy.persist();
        }

        println!(
            "[gdpr] Art.17 Self-Delete: User {} (Wallet {}) — {} DM + {} Gruppen geloescht",
            user_id,
            &wallet[..12.min(wallet.len())],
            dm_purged,
            group_purged,
        );
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "message": format!("Konto {user_id} und alle Daten gelöscht (DSGVO Art. 17)"),
            "gdpr": {
                "wallet": wallet,
                "messages_purged": dm_purged,
                "group_messages_purged": group_purged,
                "contacts_removed": contacts_removed,
            }
        })),
    ))
}
