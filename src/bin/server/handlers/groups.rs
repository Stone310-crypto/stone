//! Gruppenchat-Handler – Erstellen, Verwalten und Nachrichtenversand in Chatgruppen.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use stone::chat::{
    ChatGroup, GroupChatEntry, GroupMember, GroupRole,
    save_chat_groups,
};

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub members: Vec<String>, // Wallet-Adressen der Mitglieder
}

#[derive(Deserialize)]
pub struct GroupSendRequest {
    pub encrypted_content: String,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub wallet: String,
}

#[derive(Deserialize)]
pub struct GroupMessagesQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/chat/groups — Neue Chatgruppe erstellen
pub async fn handle_create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<CreateGroupRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let name = req.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Gruppenname muss 1-100 Zeichen lang sein"})),
        ).into_response();
    }

    if req.members.len() < 2 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Mindestens 2 Mitglieder erforderlich"})),
        ).into_response();
    }

    if req.members.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "Maximal 256 Mitglieder pro Gruppe"})),
        ).into_response();
    }

    let now = chrono::Utc::now().timestamp();
    let group_id = uuid::Uuid::new_v4().to_string();

    // Ersteller als Admin hinzufügen
    let mut members = vec![GroupMember {
        wallet: user.wallet_address.clone(),
        user_id: user.id.clone(),
        name: user.name.clone(),
        role: GroupRole::Admin,
        joined_at: now,
    }];

    // User-Daten der Mitglieder auflösen
    {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        for wallet in &req.members {
            if wallet == &user.wallet_address {
                continue; // Ersteller schon drin
            }
            let (uid, uname) = users
                .iter()
                .find(|u| &u.wallet_address == wallet)
                .map(|u| (u.id.clone(), u.name.clone()))
                .unwrap_or_else(|| (String::new(), format!("{}…", &wallet[..8.min(wallet.len())])));

            members.push(GroupMember {
                wallet: wallet.clone(),
                user_id: uid,
                name: uname,
                role: GroupRole::Member,
                joined_at: now,
            });
        }
    }

    let group = ChatGroup {
        id: group_id.clone(),
        name: name.clone(),
        creator_wallet: user.wallet_address.clone(),
        members,
        messages: Vec::new(),
        created_at: now,
    };

    {
        let mut store = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
        store.groups.push(group);
        save_chat_groups(&store);
    }

    (
        StatusCode::CREATED,
        axum::Json(json!({
            "ok": true,
            "group_id": group_id,
            "name": name,
        })),
    ).into_response()
}

/// GET /api/v1/chat/groups — Eigene Gruppen auflisten
pub async fn handle_list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let store = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
    let groups: Vec<_> = store.groups_for(&user.wallet_address)
        .into_iter()
        .map(|g| {
            let last_msg = g.messages.last();
            json!({
                "id": g.id,
                "name": g.name,
                "members_count": g.members.len(),
                "creator_wallet": g.creator_wallet,
                "created_at": g.created_at,
                "last_message_preview": last_msg.map(|m| m.encrypted_content.as_str()).unwrap_or(""),
                "last_timestamp": last_msg.map(|m| m.timestamp).unwrap_or(0),
                "total_messages": g.messages.len(),
            })
        })
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "groups": groups,
            "count": groups.len(),
        })),
    ).into_response()
}

/// GET /api/v1/chat/groups/:group_id — Gruppen-Info
pub async fn handle_get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let store = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
    let group = match store.find(&group_id) {
        Some(g) => g,
        None => return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Gruppe nicht gefunden"})),
        ).into_response(),
    };

    if !group.is_member(&user.wallet_address) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"ok": false, "error": "Kein Mitglied dieser Gruppe"})),
        ).into_response();
    }

    let members: Vec<_> = group.members.iter().map(|m| json!({
        "wallet": m.wallet,
        "user_id": m.user_id,
        "name": m.name,
        "role": m.role,
        "joined_at": m.joined_at,
    })).collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "group": {
                "id": group.id,
                "name": group.name,
                "creator_wallet": group.creator_wallet,
                "created_at": group.created_at,
                "members": members,
                "members_count": group.members.len(),
                "total_messages": group.messages.len(),
            }
        })),
    ).into_response()
}

/// POST /api/v1/chat/groups/:group_id/send — Nachricht in Gruppe senden
pub async fn handle_group_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    axum::Json(req): axum::Json<GroupSendRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if req.encrypted_content.is_empty() || req.nonce.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "encrypted_content und nonce sind Pflichtfelder"})),
        ).into_response();
    }

    let now = chrono::Utc::now().timestamp();
    let msg_id = {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(user.wallet_address.as_bytes());
        h.update(group_id.as_bytes());
        h.update(req.encrypted_content.as_bytes());
        h.update(req.nonce.as_bytes());
        h.update(now.to_le_bytes());
        format!("{:x}", h.finalize())
    };

    let entry = GroupChatEntry {
        msg_id: msg_id.clone(),
        group_id: group_id.clone(),
        from_wallet: user.wallet_address.clone(),
        from_user_id: user.id.clone(),
        from_name: user.name.clone(),
        encrypted_content: req.encrypted_content,
        nonce: req.nonce,
        timestamp: now,
    };

    {
        let mut store = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = match store.find_mut(&group_id) {
            Some(g) => g,
            None => return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "Gruppe nicht gefunden"})),
            ).into_response(),
        };

        if !group.is_member(&user.wallet_address) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"ok": false, "error": "Kein Mitglied dieser Gruppe"})),
            ).into_response();
        }

        group.add_message(entry);
        save_chat_groups(&store);
    }

    // WebSocket-Push
    state.node.events.publish(stone::master::NodeEvent::ChatMessageReceived {
        msg_id: msg_id.clone(),
        from_wallet: user.wallet_address.clone(),
        to_wallet: String::new(),
        from_name: user.name.clone(),
        timestamp: now,
        channel_type: "group".to_string(),
        group_id: group_id.clone(),
    });

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "msg_id": msg_id,
            "group_id": group_id,
        })),
    ).into_response()
}

/// GET /api/v1/chat/groups/:group_id/messages — Nachrichten einer Gruppe
pub async fn handle_group_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Query(q): Query<GroupMessagesQuery>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let store = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
    let group = match store.find(&group_id) {
        Some(g) => g,
        None => return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Gruppe nicht gefunden"})),
        ).into_response(),
    };

    if !group.is_member(&user.wallet_address) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"ok": false, "error": "Kein Mitglied dieser Gruppe"})),
        ).into_response();
    }

    let total = group.messages.len();
    let messages: Vec<_> = group.messages.iter()
        .rev()
        .skip(q.offset)
        .take(q.limit)
        .rev()
        .map(|m| json!({
            "msg_id": m.msg_id,
            "from_wallet": m.from_wallet,
            "from_user_id": m.from_user_id,
            "from_name": m.from_name,
            "encrypted_content": m.encrypted_content,
            "nonce": m.nonce,
            "timestamp": m.timestamp,
        }))
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "group_id": group_id,
            "messages": messages,
            "count": messages.len(),
            "total": total,
        })),
    ).into_response()
}

/// POST /api/v1/chat/groups/:group_id/members — Mitglied hinzufügen
pub async fn handle_add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    axum::Json(req): axum::Json<AddMemberRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if req.wallet.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "wallet ist Pflichtfeld"})),
        ).into_response();
    }

    let now = chrono::Utc::now().timestamp();

    // User-Daten des neuen Mitglieds auflösen
    let (uid, uname) = {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        users.iter()
            .find(|u| u.wallet_address == req.wallet)
            .map(|u| (u.id.clone(), u.name.clone()))
            .unwrap_or_else(|| (String::new(), format!("{}…", &req.wallet[..8.min(req.wallet.len())])))
    };

    let new_member = GroupMember {
        wallet: req.wallet.clone(),
        user_id: uid,
        name: uname,
        role: GroupRole::Member,
        joined_at: now,
    };

    {
        let mut store = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = match store.find_mut(&group_id) {
            Some(g) => g,
            None => return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "Gruppe nicht gefunden"})),
            ).into_response(),
        };

        if !group.is_admin(&user.wallet_address) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"ok": false, "error": "Nur Admins können Mitglieder hinzufügen"})),
            ).into_response();
        }

        if let Err(e) = group.add_member(new_member) {
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({"ok": false, "error": e})),
            ).into_response();
        }

        save_chat_groups(&store);
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "message": "Mitglied hinzugefügt",
        })),
    ).into_response()
}

/// DELETE /api/v1/chat/groups/:group_id/members/:wallet — Mitglied entfernen
pub async fn handle_remove_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((group_id, wallet)): Path<(String, String)>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    {
        let mut store = state.chat_groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = match store.find_mut(&group_id) {
            Some(g) => g,
            None => return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "Gruppe nicht gefunden"})),
            ).into_response(),
        };

        // Selbst verlassen ist erlaubt, ansonsten nur Admins
        if wallet != user.wallet_address && !group.is_admin(&user.wallet_address) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"ok": false, "error": "Nur Admins können andere Mitglieder entfernen"})),
            ).into_response();
        }

        if let Err(e) = group.remove_member(&wallet) {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"ok": false, "error": e})),
            ).into_response();
        }

        save_chat_groups(&store);
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "message": "Mitglied entfernt",
        })),
    ).into_response()
}
