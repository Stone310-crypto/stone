//! Organisation handlers: create, list, invite, join, leave, chat, channels.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use stone::organization::{save_orgs, ChatMessage, OrgRole, Organization};

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

// ─── Request-Typen ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize)]
pub struct InviteRequest {
    pub target_user_id: String,
    #[serde(default = "default_role_str")]
    pub role: String,
}

fn default_role_str() -> String {
    "member".to_string()
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub user_id: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct RemoveMemberRequest {
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
    #[serde(default = "default_channel_type")]
    pub channel_type: String,
}

fn default_channel_type() -> String {
    "both".to_string()
}

#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub channel_id: String,
    /// AES-256-GCM verschlüsselter Nachrichtentext (base64)
    pub encrypted_content: String,
    /// AES-256-GCM Nonce (base64, 12 Bytes)
    pub nonce: String,
    #[serde(default)]
    pub reply_to: String,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /api/v1/orgs — Organisation erstellen
pub async fn handle_create_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<CreateOrgRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Organisation-Name darf nicht leer sein"})),
        )
            .into_response();
    }

    let org = Organization::create(
        req.name.trim(),
        req.description.trim(),
        &user.id,
        &user.name,
    );
    let org_id = org.id.clone();

    {
        let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
        orgs.push(org.clone());
        save_orgs(&orgs);
    }

    // User-Profil aktualisieren
    {
        let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(u) = users.iter_mut().find(|u| u.id == user.id) {
            u.account_type = "organization".to_string();
            u.org_id = org_id.clone();
            u.org_role = "owner".to_string();
        }
        stone::auth::save_users(&users);
    }

    println!(
        "[orgs] 🏢 Organisation '{}' erstellt von {} ({})",
        req.name.trim(),
        user.name,
        org_id
    );

    (
        StatusCode::CREATED,
        axum::Json(json!({
            "ok": true,
            "org": {
                "id": org.id,
                "name": org.name,
                "description": org.description,
                "owner_id": org.owner_id,
                "created_at": org.created_at,
                "members": org.members.len(),
                "channels": org.channels.iter().map(|c| &c.name).collect::<Vec<_>>(),
            }
        })),
    )
        .into_response()
}

/// GET /api/v1/orgs — Organisationen des Users auflisten
pub async fn handle_list_orgs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let my_orgs: Vec<serde_json::Value> = orgs
        .iter()
        .filter(|o| o.is_member(&user.id))
        .map(|o| {
            let role = o.member_role(&user.id).map(|r| r.to_string()).unwrap_or_default();
            json!({
                "id": o.id,
                "name": o.name,
                "description": o.description,
                "owner_id": o.owner_id,
                "created_at": o.created_at,
                "my_role": role,
                "members": o.members.len(),
                "channels": o.channels.len(),
            })
        })
        .collect();

    (StatusCode::OK, axum::Json(json!({"orgs": my_orgs}))).into_response()
}

/// GET /api/v1/orgs/:org_id — Organisation-Details
pub async fn handle_get_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    if !org.is_member(&user.id) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Kein Mitglied dieser Organisation"})),
        )
            .into_response();
    }

    let members: Vec<serde_json::Value> = org
        .members
        .iter()
        .map(|m| {
            json!({
                "user_id": m.user_id,
                "display_name": m.display_name,
                "role": m.role.to_string(),
                "joined_at": m.joined_at,
            })
        })
        .collect();

    let channels: Vec<serde_json::Value> = org
        .channels
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "channel_type": c.channel_type,
                "created_at": c.created_at,
            })
        })
        .collect();

    let invites: Vec<serde_json::Value> = org
        .invites
        .iter()
        .filter(|i| i.status == stone::organization::InviteStatus::Pending)
        .map(|i| {
            json!({
                "invite_id": i.invite_id,
                "target_user_id": i.target_user_id,
                "invited_by": i.invited_by,
                "role": i.role.to_string(),
                "created_at": i.created_at,
                "expires_at": i.expires_at,
            })
        })
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "org": {
                "id": org.id,
                "name": org.name,
                "description": org.description,
                "owner_id": org.owner_id,
                "created_at": org.created_at,
                "encrypted_org_key": org.encrypted_org_key,
                "org_key_nonce": org.org_key_nonce,
            },
            "members": members,
            "channels": channels,
            "invites": invites,
        })),
    )
        .into_response()
}

/// POST /api/v1/orgs/:org_id/invite — Benutzer einladen
pub async fn handle_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    axum::Json(req): axum::Json<InviteRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Prüfe ob der Ziel-User existiert
    {
        let users = state.users.lock().unwrap_or_else(|e| e.into_inner());
        if !users.iter().any(|u| u.id == req.target_user_id) {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Benutzer nicht gefunden"})),
            )
                .into_response();
        }
    }

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter_mut().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    let role = OrgRole::from_str(&req.role);
    match org.invite_user(&req.target_user_id, role, &user.id) {
        Ok(invite) => {
            save_orgs(&orgs);
            println!(
                "[orgs] 📨 Einladung {} → {} in {}",
                invite.invite_id, req.target_user_id, org_id
            );
            (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "invite": {
                        "invite_id": invite.invite_id,
                        "target_user_id": invite.target_user_id,
                        "role": invite.role.to_string(),
                        "expires_at": invite.expires_at,
                    }
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// GET /api/v1/orgs/invites — Eigene offene Einladungen
pub async fn handle_my_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let mut invites: Vec<serde_json::Value> = Vec::new();

    for org in orgs.iter() {
        for inv in &org.invites {
            if inv.target_user_id == user.id
                && inv.status == stone::organization::InviteStatus::Pending
            {
                invites.push(json!({
                    "invite_id": inv.invite_id,
                    "org_id": inv.org_id,
                    "org_name": org.name,
                    "invited_by": inv.invited_by,
                    "role": inv.role.to_string(),
                    "created_at": inv.created_at,
                    "expires_at": inv.expires_at,
                }));
            }
        }
    }

    (StatusCode::OK, axum::Json(json!({"invites": invites}))).into_response()
}

/// POST /api/v1/orgs/invites/:invite_id/accept — Einladung annehmen
pub async fn handle_accept_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let org = orgs.iter_mut().find(|o| {
        o.invites
            .iter()
            .any(|i| i.invite_id == invite_id && i.target_user_id == user.id)
    });

    let Some(org) = org else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Einladung nicht gefunden"})),
        )
            .into_response();
    };

    let org_id = org.id.clone();
    let org_name = org.name.clone();

    match org.accept_invite(&invite_id, &user.id, &user.name) {
        Ok(()) => {
            save_orgs(&orgs);
            drop(orgs);

            // User-Profil aktualisieren
            {
                let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(u) = users.iter_mut().find(|u| u.id == user.id) {
                    u.org_id = org_id.clone();
                    u.org_role = "member".to_string();
                }
                stone::auth::save_users(&users);
            }

            println!(
                "[orgs] ✅ {} hat Einladung für '{}' angenommen",
                user.name, org_name
            );

            (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "org_id": org_id,
                    "org_name": org_name,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/v1/orgs/invites/:invite_id/decline — Einladung ablehnen
pub async fn handle_decline_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let org = orgs.iter_mut().find(|o| {
        o.invites
            .iter()
            .any(|i| i.invite_id == invite_id && i.target_user_id == user.id)
    });

    let Some(org) = org else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Einladung nicht gefunden"})),
        )
            .into_response();
    };

    match org.decline_invite(&invite_id, &user.id) {
        Ok(()) => {
            save_orgs(&orgs);
            (StatusCode::OK, axum::Json(json!({"ok": true}))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/v1/orgs/:org_id/leave — Organisation verlassen
pub async fn handle_leave_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter_mut().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    match org.leave(&user.id) {
        Ok(()) => {
            save_orgs(&orgs);
            drop(orgs);

            // User-Profil bereinigen
            {
                let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(u) = users.iter_mut().find(|u| u.id == user.id) {
                    if u.org_id == org_id {
                        u.org_id.clear();
                        u.org_role.clear();
                    }
                }
                stone::auth::save_users(&users);
            }

            println!("[orgs] 👋 {} hat '{}' verlassen", user.name, org_id);

            (StatusCode::OK, axum::Json(json!({"ok": true}))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/v1/orgs/:org_id/members/remove — Mitglied entfernen (Admin/Owner)
pub async fn handle_remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    axum::Json(req): axum::Json<RemoveMemberRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter_mut().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    match org.remove_member(&req.user_id, &user.id) {
        Ok(()) => {
            save_orgs(&orgs);
            drop(orgs);

            // Entfernten User bereinigen
            {
                let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(u) = users.iter_mut().find(|u| u.id == req.user_id) {
                    if u.org_id == org_id {
                        u.org_id.clear();
                        u.org_role.clear();
                    }
                }
                stone::auth::save_users(&users);
            }

            println!(
                "[orgs] ❌ {} wurde aus '{}' entfernt von {}",
                req.user_id, org_id, user.name
            );
            (StatusCode::OK, axum::Json(json!({"ok": true}))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/v1/orgs/:org_id/members/role — Rolle ändern (Admin/Owner)
pub async fn handle_set_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    axum::Json(req): axum::Json<SetRoleRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let new_role = OrgRole::from_str(&req.role);

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter_mut().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    match org.set_member_role(&req.user_id, new_role, &user.id) {
        Ok(()) => {
            // Neue Rolle lesen für die Antwort
            let role_str = org
                .member_role(&req.user_id)
                .map(|r| r.to_string())
                .unwrap_or_default();
            save_orgs(&orgs);
            drop(orgs);

            // User-Profil aktualisieren
            {
                let mut users = state.users.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(u) = users.iter_mut().find(|u| u.id == req.user_id) {
                    u.org_role = role_str.clone();
                }
                stone::auth::save_users(&users);
            }

            (
                StatusCode::OK,
                axum::Json(json!({"ok": true, "new_role": role_str})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/v1/orgs/:org_id/channels — Channel erstellen
pub async fn handle_create_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    axum::Json(req): axum::Json<CreateChannelRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Channel-Name darf nicht leer sein"})),
        )
            .into_response();
    }

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter_mut().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    match org.create_channel(req.name.trim(), &req.channel_type, &user.id) {
        Ok(ch) => {
            save_orgs(&orgs);
            (
                StatusCode::CREATED,
                axum::Json(json!({
                    "ok": true,
                    "channel": {
                        "id": ch.id,
                        "name": ch.name,
                        "channel_type": ch.channel_type,
                    }
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/v1/orgs/:org_id/chat — Nachricht senden (verschlüsselt)
pub async fn handle_send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    axum::Json(req): axum::Json<SendMessageRequest>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let now = chrono::Utc::now().timestamp();
    let msg_id = format!("msg-{}", &uuid::Uuid::new_v4().to_string()[..12]);

    let msg = ChatMessage {
        msg_id: msg_id.clone(),
        org_id: org_id.clone(),
        channel_id: req.channel_id.clone(),
        sender_id: user.id.clone(),
        sender_name: user.name.clone(),
        encrypted_content: req.encrypted_content,
        nonce: req.nonce,
        timestamp: now,
        reply_to: req.reply_to,
        deleted: false,
    };

    let mut orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter_mut().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    match org.add_chat_message(msg) {
        Ok(()) => {
            save_orgs(&orgs);
            (
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "msg_id": msg_id,
                    "timestamp": now,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": e})),
        )
            .into_response(),
    }
}

/// GET /api/v1/orgs/:org_id/chat/:channel_id — Chat-Verlauf lesen
pub async fn handle_get_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((org_id, channel_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let user = match require_user(&headers, &state) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let orgs = state.orgs.lock().unwrap_or_else(|e| e.into_inner());
    let Some(org) = orgs.iter().find(|o| o.id == org_id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Organisation nicht gefunden"})),
        )
            .into_response();
    };

    if !org.is_member(&user.id) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Kein Mitglied dieser Organisation"})),
        )
            .into_response();
    }

    // Prüfe ob User Leserechte für diesen Channel hat
    if let Some(member) = org.members.iter().find(|m| m.user_id == user.id) {
        if let Some(perm) = member.channel_permissions.get(&channel_id) {
            if !perm.read {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "Keine Leserechte für diesen Channel"})),
                )
                    .into_response();
            }
        }
    }

    let messages: Vec<serde_json::Value> = org
        .chat_history(&channel_id, 200)
        .iter()
        .map(|m| {
            json!({
                "msg_id": m.msg_id,
                "sender_id": m.sender_id,
                "sender_name": m.sender_name,
                "encrypted_content": m.encrypted_content,
                "nonce": m.nonce,
                "timestamp": m.timestamp,
                "reply_to": m.reply_to,
            })
        })
        .collect();

    (
        StatusCode::OK,
        axum::Json(json!({
            "channel_id": channel_id,
            "messages": messages,
        })),
    )
        .into_response()
}
