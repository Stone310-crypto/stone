//! Watchdog Handler
//!
//! POST /api/v1/sdk/watchdog/client-proof    – Plugin-Integrität prüfen
//! POST /api/v1/sdk/watchdog/behavior-report – Verhaltens-Violations melden

use axum::{Json, extract::State, http::HeaderMap};
use serde_json::json;
use stone::watchdog::{BehaviorReport, ClientHashProof, TrustLevel};

use super::super::state::AppState;
use super::game::validate_sdk_key_for_watchdog;

// ── POST /api/v1/sdk/watchdog/client-proof ────────────────────────────────────

pub async fn handle_watchdog_client_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(proof): Json<ClientHashProof>,
) -> Json<serde_json::Value> {
    let game_id = match validate_sdk_key_for_watchdog(&state, &headers) {
        Ok(id) => id,
        Err(e) => return Json(json!({ "ok": false, "error": e })),
    };

    if proof.game_id != game_id {
        return Json(json!({
            "ok": false,
            "error": "game_id stimmt nicht mit SDK-Key überein"
        }));
    }

    let (trust_level, rejection_reason) = state.watchdog.verify_proof(&proof);

    let is_rejected = trust_level == TrustLevel::Rejected;

    if is_rejected {
        eprintln!(
            "[watchdog] REJECTED proof game={} pub_key={}... reason={}",
            proof.game_id,
            &proof.public_key_hex[..proof.public_key_hex.len().min(16)],
            rejection_reason.as_deref().unwrap_or("unknown"),
        );
    } else {
        let flag_str = if proof.suspicious_flags.is_empty() {
            String::new()
        } else {
            format!(" flags={:?}", proof.suspicious_flags)
        };
        eprintln!(
            "[watchdog] {} proof game={} pub_key={}... hash={}...{}",
            trust_level,
            proof.game_id,
            &proof.public_key_hex[..proof.public_key_hex.len().min(16)],
            &proof.plugin_hash[..proof.plugin_hash.len().min(16)],
            flag_str,
        );
    }

    Json(json!({
        "ok": !is_rejected,
        "verified": !is_rejected,
        "trust_level": trust_level.to_string(),
        "suspicious_flags": proof.suspicious_flags,
        "rejection_reason": rejection_reason,
        "verified_clients_total": state.watchdog.verified_count(),
    }))
}

// ── POST /api/v1/sdk/watchdog/behavior-report ─────────────────────────────────

pub async fn handle_watchdog_behavior_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(report): Json<BehaviorReport>,
) -> Json<serde_json::Value> {
    let game_id = match validate_sdk_key_for_watchdog(&state, &headers) {
        Ok(id) => id,
        Err(e) => return Json(json!({ "ok": false, "error": e })),
    };

    if report.game_id != game_id {
        return Json(json!({ "ok": false, "error": "game_id stimmt nicht mit SDK-Key überein" }));
    }

    if report.violations.is_empty() {
        return Json(json!({ "ok": true, "stored": 0, "newly_flagged": 0 }));
    }

    let count = report.violations.len();
    let newly_flagged = state.watchdog.record_violations(&report);

    // Detailliertes Logging
    for v in &report.violations {
        let conf_pct = (v.confidence * 100.0) as u32;
        eprintln!(
            "[watchdog] violation game={} player={} type={} conf={}% details={}",
            game_id, v.player_name, v.violation, conf_pct, v.details
        );
    }

    Json(json!({
        "ok": true,
        "stored": count,
        "newly_flagged": newly_flagged,
        "total_flagged": state.watchdog.flagged_player_count(),
    }))
}
