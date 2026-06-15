//! Community Announcement Channel – Read-only Kanal für Gründer-Nachrichten.
//!
//! Nur autorisierte Gründer (via Ed25519-Signatur) dürfen posten.
//! Alle User können lesen, reagieren (Emoji) und bei Polls abstimmen.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::json;
use stone::chat::{Announcement, AnnouncementType, PollOption, save_announcements};

use super::super::state::AppState;

// ─── Request-Typen ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateAnnouncementRequest {
    pub title: String,
    pub content: String,
    pub announcement_type: AnnouncementType,
    pub signature: String,
    pub author_pubkey: String,
    /// Unix-Timestamp der beim Signieren verwendet wurde.
    pub timestamp: i64,
    /// Poll-Optionen (nur bei `announcement_type: "poll"`).
    pub poll_options: Option<Vec<String>>,
    /// Optionale Deadline (Unix-Timestamp) für zeitlich begrenzte Polls.
    pub deadline: Option<i64>,
}

#[derive(Deserialize)]
pub struct ReactRequest {
    pub emoji: String,
    /// Wallet-Adresse des reagierenden Users.
    pub wallet: String,
}

#[derive(Deserialize)]
pub struct VoteRequest {
    pub option_id: String,
    /// Wallet-Adresse des abstimmenden Users.
    pub wallet: String,
}

#[derive(Deserialize)]
pub struct AnnouncementPagination {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// ─── Erlaubte Emojis ──────────────────────────────────────────────────────────

const ALLOWED_EMOJIS: &[&str] = &["👍", "❤️", "🔥", "🎉", "👀", "💎", "🚀", "⛏️"];

// ─── Handler ──────────────────────────────────────────────────────────────────

/// GET /api/v1/announcements — Alle Announcements abrufen (öffentlich, kein Auth).
pub async fn handle_list_announcements(
    State(state): State<AppState>,
    Query(params): Query<AnnouncementPagination>,
) -> impl IntoResponse {
    let store = state.announcements.lock().unwrap_or_else(|e| e.into_inner());
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // Neueste zuerst
    let total = store.announcements.len();
    let mut sorted: Vec<&Announcement> = store.announcements.iter().collect();
    sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let page: Vec<_> = sorted.into_iter().skip(offset).take(limit).collect();

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "announcements": page,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
    .into_response()
}

/// GET /api/v1/announcements/{id} — Einzelnes Announcement abrufen (öffentlich).
pub async fn handle_get_announcement(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let store = state.announcements.lock().unwrap_or_else(|e| e.into_inner());
    match store.find(&id) {
        Some(a) => (StatusCode::OK, axum::Json(json!({
            "ok": true,
            "announcement": a,
        })))
        .into_response(),
        None => (StatusCode::NOT_FOUND, axum::Json(json!({
            "ok": false,
            "error": "Announcement nicht gefunden",
        })))
        .into_response(),
    }
}

/// POST /api/v1/announcements — Neues Announcement posten (Gründer-Signatur erforderlich).
pub async fn handle_create_announcement(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<CreateAnnouncementRequest>,
) -> impl IntoResponse {
    // Validierung
    let title = req.title.trim();
    let content = req.content.trim();
    if title.is_empty() || title.len() > 200 {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Titel muss 1-200 Zeichen lang sein",
        })))
        .into_response();
    }
    if content.is_empty() || content.len() > 10_000 {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Inhalt muss 1-10000 Zeichen lang sein",
        })))
        .into_response();
    }

    // Pubkey-Autorisierung prüfen
    {
        let store = state.announcements.lock().unwrap_or_else(|e| e.into_inner());
        if !store.is_founder(&req.author_pubkey) {
            return (StatusCode::FORBIDDEN, axum::Json(json!({
                "ok": false, "error": "Pubkey ist nicht als Gründer autorisiert",
            })))
            .into_response();
        }
    }

    // Ed25519-Signatur verifizieren
    // Client-Timestamp verwenden (±5 Minuten Toleranz gegen Replay-Angriffe)
    let now = chrono::Utc::now().timestamp();
    if (req.timestamp - now).abs() > 300 {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Timestamp zu alt oder in der Zukunft (max. 5 Minuten)",
        })))
        .into_response();
    }
    let timestamp = req.timestamp;
    let msg = Announcement::signing_message(title, content, timestamp);

    let pub_bytes = match hex::decode(&req.author_pubkey) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Ungültiger Public Key (64 Hex-Zeichen erwartet)",
        })))
        .into_response(),
    };
    let pub_array: [u8; 32] = pub_bytes.try_into().unwrap();
    let verifying_key = match VerifyingKey::from_bytes(&pub_array) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Ungültiger Ed25519 Public Key",
        })))
        .into_response(),
    };

    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Ungültige Signatur (128 Hex-Zeichen erwartet)",
        })))
        .into_response(),
    };
    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_array);

    if verifying_key.verify_strict(&msg, &signature).is_err() {
        return (StatusCode::FORBIDDEN, axum::Json(json!({
            "ok": false, "error": "Signatur-Verifikation fehlgeschlagen",
        })))
        .into_response();
    }

    // Poll-Optionen vorbereiten
    let poll_options = if req.announcement_type == AnnouncementType::Poll {
        match &req.poll_options {
            Some(opts) if opts.len() >= 2 && opts.len() <= 10 => {
                Some(opts.iter().enumerate().map(|(i, text)| PollOption {
                    id: format!("opt-{}", i),
                    text: text.trim().to_string(),
                    votes: Vec::new(),
                }).collect())
            }
            _ => return (StatusCode::BAD_REQUEST, axum::Json(json!({
                "ok": false, "error": "Poll benötigt 2-10 Optionen",
            })))
            .into_response(),
        }
    } else {
        None
    };

    // Deadline Validierung (falls angegeben, muss in der Zukunft liegen)
    if let Some(dl) = req.deadline {
        if dl <= now {
            return (StatusCode::BAD_REQUEST, axum::Json(json!({
                "ok": false, "error": "Deadline muss in der Zukunft liegen",
            })))
            .into_response();
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let announcement = Announcement {
        id: id.clone(),
        title: title.to_string(),
        content: content.to_string(),
        announcement_type: req.announcement_type,
        timestamp,
        signature: req.signature,
        author_pubkey: req.author_pubkey,
        poll_options,
        reactions: Default::default(),
        deadline: req.deadline,
    };

    let mut store = state.announcements.lock().unwrap_or_else(|e| e.into_inner());
    store.announcements.push(announcement.clone());
    save_announcements(&store);

    // Push-Benachrichtigung an alle registrierten Geräte senden (Fire & Forget)
    {
        let push_store = state.push_tokens.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let fcm = state.fcm_client.clone();
        tokio::spawn(async move {
            let sent = fcm.broadcast(&push_store, &stone::push::PushType::Announcement).await;
            if sent > 0 {
                println!("[push] 📬 Announcement-Push an {sent} Geräte gesendet");
            }
        });
    }

    (StatusCode::CREATED, axum::Json(json!({
        "ok": true,
        "announcement": announcement,
    })))
    .into_response()
}

/// DELETE /api/v1/announcements/{id} — Announcement löschen (Gründer-Signatur erforderlich).
pub async fn handle_delete_announcement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Auth: Nur Admin kann löschen
    if let Err(e) = super::super::auth_middleware::require_admin(&headers, &state) {
        return e;
    }

    let mut store = state.announcements.lock().unwrap_or_else(|e| e.into_inner());
    let before = store.announcements.len();
    store.announcements.retain(|a| a.id != id);
    if store.announcements.len() == before {
        return (StatusCode::NOT_FOUND, axum::Json(json!({
            "ok": false, "error": "Announcement nicht gefunden",
        })))
        .into_response();
    }
    save_announcements(&store);

    (StatusCode::OK, axum::Json(json!({ "ok": true })))
        .into_response()
}

/// POST /api/v1/announcements/{id}/react — Emoji-Reaktion hinzufügen/entfernen (Toggle).
pub async fn handle_react(
    State(state): State<AppState>,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<ReactRequest>,
) -> impl IntoResponse {
    let wallet = req.wallet.trim().to_string();
    if wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "wallet darf nicht leer sein",
        })))
        .into_response();
    }

    if !ALLOWED_EMOJIS.contains(&req.emoji.as_str()) {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Emoji nicht erlaubt",
            "allowed": ALLOWED_EMOJIS,
        })))
        .into_response();
    }

    let mut store = state.announcements.lock().unwrap_or_else(|e| e.into_inner());
    let announcement = match store.find_mut(&id) {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, axum::Json(json!({
            "ok": false, "error": "Announcement nicht gefunden",
        })))
        .into_response(),
    };

    let wallets = announcement.reactions.entry(req.emoji.clone()).or_default();
    if let Some(pos) = wallets.iter().position(|w| w == &wallet) {
        wallets.remove(pos); // Toggle off
    } else {
        wallets.push(wallet.clone()); // Toggle on
    }

    let reactions = announcement.reactions.clone();
    save_announcements(&store);

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "reactions": reactions,
    })))
    .into_response()
}

/// POST /api/v1/announcements/{id}/vote — Bei Poll abstimmen (1 Vote pro Wallet).
pub async fn handle_vote(
    State(state): State<AppState>,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<VoteRequest>,
) -> impl IntoResponse {
    let wallet = req.wallet.trim().to_string();
    if wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "wallet darf nicht leer sein",
        })))
        .into_response();
    }

    let mut store = state.announcements.lock().unwrap_or_else(|e| e.into_inner());
    let announcement = match store.find_mut(&id) {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, axum::Json(json!({
            "ok": false, "error": "Announcement nicht gefunden",
        })))
        .into_response(),
    };

    if announcement.announcement_type != AnnouncementType::Poll {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Dieses Announcement ist kein Poll",
        })))
        .into_response();
    }

    // Deadline prüfen
    if let Some(deadline) = announcement.deadline {
        let now = chrono::Utc::now().timestamp();
        if now > deadline {
            return (StatusCode::BAD_REQUEST, axum::Json(json!({
                "ok": false, "error": "Die Abstimmung ist abgelaufen",
            })))
            .into_response();
        }
    }

    let options = match &mut announcement.poll_options {
        Some(opts) => opts,
        None => return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Poll hat keine Optionen",
        })))
        .into_response(),
    };

    // Prüfen ob der User schon abgestimmt hat (bei irgendeiner Option)
    let already_voted = options.iter().any(|opt|
        opt.votes.contains(&wallet)
    );
    if already_voted {
        return (StatusCode::CONFLICT, axum::Json(json!({
            "ok": false, "error": "Du hast bereits abgestimmt",
        })))
        .into_response();
    }

    // Option finden und Vote eintragen
    let option = match options.iter_mut().find(|o| o.id == req.option_id) {
        Some(o) => o,
        None => return (StatusCode::BAD_REQUEST, axum::Json(json!({
            "ok": false, "error": "Option nicht gefunden",
        })))
        .into_response(),
    };
    option.votes.push(wallet.clone());

    let poll_options = announcement.poll_options.clone().unwrap_or_default();
    save_announcements(&store);

    (StatusCode::OK, axum::Json(json!({
        "ok": true,
        "poll_options": poll_options,
    })))
    .into_response()
}
