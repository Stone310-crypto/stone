//! Audio-Relay: WebSocket-basierter Audio-Relay für Sprachanrufe.
//!
//! Zwei Peers verbinden sich per call_id. Binäre Audio-Frames
//! werden direkt zwischen ihnen weitergeleitet (der Server dekodiert
//! das Audio nicht – reines Relay).
//!
//! Optimiert für 5.000+ gleichzeitige Calls:
//! - DashMap statt Mutex<HashMap> (lock-free concurrent Room-Access)
//! - Bytes statt Vec<u8> (zero-copy Audio-Frame-Relay)
//! - Arc<str> für Wallet-IDs (keine String-Clones pro Frame)
//! - Idle-Timeout: Rooms werden nach 5 Min Inaktivität entfernt

use axum::{
    extract::{Path, Query, State},
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
};
use bytes::Bytes;
use dashmap::DashMap;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::broadcast;

use super::super::auth_middleware::{resolve_user_by_session_token, resolve_user_by_key};
use super::super::state::AppState;

// ─── Types ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AudioRelayQuery {
    /// Session token (Bearer token) for authentication
    pub token: Option<String>,
    /// API key fallback
    pub api_key: Option<String>,
}

pub(crate) struct AudioRoom {
    tx: broadcast::Sender<(Arc<str>, Bytes)>,
    /// Unix-Timestamp des letzten Audio-Frames (für Idle-Timeout)
    last_activity: AtomicI64,
}

/// Lock-freier Store für aktive Audio-Rooms (DashMap = concurrent HashMap)
pub type AudioRooms = Arc<DashMap<String, AudioRoom>>;

pub fn new_audio_rooms() -> AudioRooms {
    Arc::new(DashMap::new())
}

/// Idle-Rooms aufräumen (aufrufen per Intervall-Task, z.B. alle 60s)
pub fn gc_idle_rooms(rooms: &AudioRooms) {
    let now = chrono::Utc::now().timestamp();
    const IDLE_TIMEOUT_SECS: i64 = 300; // 5 Minuten
    rooms.retain(|call_id, room| {
        let last = room.last_activity.load(Ordering::Relaxed);
        let keep = (now - last) < IDLE_TIMEOUT_SECS || room.tx.receiver_count() > 0;
        if !keep {
            println!("[audio-relay] Room {call_id} entfernt (idle > {IDLE_TIMEOUT_SECS}s)");
        }
        keep
    });
}

// ─── Handler ─────────────────────────────────────────────────────────────────

/// GET /api/v1/call/audio/{call_id}?token=<session_token>
pub async fn handle_audio_relay(
    ws: WebSocketUpgrade,
    Path(call_id): Path<String>,
    Query(query): Query<AudioRelayQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let user = if let Some(token) = &query.token {
        resolve_user_by_session_token(token, &state.users, &state.api_key)
    } else if let Some(key) = &query.api_key {
        resolve_user_by_key(key, &state.users, &state.api_key, &state.admin_key)
    } else {
        None
    };

    let user = match user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let wallet: Arc<str> = Arc::from(user.wallet_address.as_str());
    let rooms = state.audio_rooms.clone();
    println!("[audio-relay] {} joined call {}", &wallet, call_id);

    ws.on_upgrade(move |socket| audio_relay_loop(socket, call_id, wallet, rooms))
        .into_response()
}

// ─── WebSocket Loop ──────────────────────────────────────────────────────────

async fn audio_relay_loop(
    mut socket: WebSocket,
    call_id: String,
    wallet: Arc<str>,
    rooms: AudioRooms,
) {
    // Join or create room (lock-free via DashMap)
    let (tx, mut rx) = {
        let room = rooms.entry(call_id.clone()).or_insert_with(|| {
            let (tx, _) = broadcast::channel(128);
            AudioRoom {
                tx,
                last_activity: AtomicI64::new(chrono::Utc::now().timestamp()),
            }
        });
        (room.tx.clone(), room.tx.subscribe())
    };

    loop {
        tokio::select! {
            // Peer sendet Audio → an Room broadcasten (zero-copy Bytes)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        // Bytes::from(data) – axum gibt bereits Bytes, kein Clone nötig
                        let frame = Bytes::from(data);
                        // Activity-Timestamp aktualisieren
                        if let Some(room) = rooms.get(&call_id) {
                            room.last_activity.store(
                                chrono::Utc::now().timestamp(),
                                Ordering::Relaxed,
                            );
                        }
                        let _ = tx.send((wallet.clone(), frame));
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            // Room hat Audio von anderem Peer → an diesen Peer senden
            frame = rx.recv() => {
                match frame {
                    Ok((sender, data)) if *sender != *wallet => {
                        if socket.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {} // Eigene Frames ignorieren
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("[audio-relay] {} lagged {n} frames in {}", &wallet, &call_id);
                        continue;
                    }
                }
            }
        }
    }

    println!("[audio-relay] {} left call {}", &wallet, call_id);

    // Cleanup: Room entfernen wenn leer (lock-free)
    drop(rx);
    drop(tx);
    rooms.remove_if(&call_id, |_, room| room.tx.receiver_count() == 0);
}
