//! Dashboard v2 API skeleton for custom node dashboards.
//!
//! Ziel: Stabile Contracts fuer externe Dashboard-Apps bereitstellen,
//! ohne interne Node-Modelle direkt zu leaken.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use stone::blockchain::data_dir;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::auth_middleware::{extract_bearer_token, require_admin, require_user};
use super::super::state::AppState;

const API_VERSION: &str = "2.0.0-draft";
const MANIFEST_VERSION: &str = "stone.dashboard.manifest.v1";
const DASHBOARD_TOKEN_PREFIX: &str = "sd2";

#[derive(Debug, Clone, Serialize)]
pub struct ScopeDescriptor {
    pub scope: &'static str,
    pub access: &'static str,
    pub description: &'static str,
    pub default_granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardManifest {
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub entry_url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub required_permissions: Vec<String>,
    #[serde(default)]
    pub supported_api_versions: Vec<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub default_layout: Vec<ManifestWidgetPlacement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestWidgetPlacement {
    pub widget_id: String,
    pub zone: String,
    #[serde(default)]
    pub min_w: u8,
    #[serde(default)]
    pub min_h: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub normalized: Option<DashboardManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetRegistryEntry {
    pub app_id: String,
    pub manifest: DashboardManifest,
    #[serde(default)]
    pub granted_scopes: Vec<String>,
    pub installed_at: i64,
    pub installed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardAppTokenClaims {
    pub token_id: String,
    pub app_id: String,
    pub scopes: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardAppTokenRecord {
    pub token_id: String,
    pub app_id: String,
    pub scopes: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issued_by: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallWidgetRequest {
    pub manifest: DashboardManifest,
    #[serde(default)]
    pub grant_scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppScopeQuery {
    pub app_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssueDashboardTokenRequest {
    pub app_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardTokenListQuery {
    pub app_id: Option<String>,
}

fn registry_file() -> String {
    format!("{}/dashboard_widgets_v2.json", data_dir())
}

fn token_file() -> String {
    format!("{}/dashboard_app_tokens_v2.json", data_dir())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_token_registry() -> Vec<DashboardAppTokenRecord> {
    let path = token_file();
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(entries) = serde_json::from_str::<Vec<DashboardAppTokenRecord>>(&raw) {
            return entries;
        }
    }
    Vec::new()
}

fn save_token_registry(entries: &[DashboardAppTokenRecord]) -> Result<(), String> {
    let path = token_file();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
    std::fs::write(path, body).map_err(|e| e.to_string())
}

fn dashboard_token_signing_secret(state: &AppState) -> String {
    if let Ok(secret) = std::env::var("STONE_DASHBOARD_TOKEN_SECRET") {
        let trimmed = secret.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    state.admin_key.to_string()
}

fn dashboard_token_verify_secrets(state: &AppState) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let active = dashboard_token_signing_secret(state);
    if seen.insert(active.clone()) {
        out.push(active);
    }

    if let Ok(prev) = std::env::var("STONE_DASHBOARD_TOKEN_PREVIOUS_SECRET") {
        let prev = prev.trim();
        if !prev.is_empty() {
            let prev = prev.to_string();
            if seen.insert(prev.clone()) {
                out.push(prev);
            }
        }
    }

    if let Ok(extra) = std::env::var("STONE_DASHBOARD_TOKEN_VERIFY_SECRETS") {
        for s in extra.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
            let val = s.to_string();
            if seen.insert(val.clone()) {
                out.push(val);
            }
        }
    }

    out
}

fn generate_dashboard_app_token(claims: &DashboardAppTokenClaims, secret: &str) -> Result<String, String> {
    let claims_json = serde_json::to_string(claims).map_err(|e| e.to_string())?;
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("HMAC init fehlgeschlagen: {e}"))?;
    mac.update(claims_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

    Ok(format!("{DASHBOARD_TOKEN_PREFIX}.{claims_b64}.{sig_b64}"))
}

fn parse_dashboard_app_token(token: &str, secret: &str) -> Option<DashboardAppTokenClaims> {
    let mut parts = token.splitn(3, '.');
    let prefix = parts.next()?;
    let claims_b64 = parts.next()?;
    let sig_b64 = parts.next()?;

    if prefix != DASHBOARD_TOKEN_PREFIX {
        return None;
    }

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(claims_b64.as_bytes());
    let expected = mac.finalize().into_bytes();
    let expected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected);
    if expected_b64 != sig_b64 {
        return None;
    }

    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_b64)
        .ok()?;
    let claims: DashboardAppTokenClaims = serde_json::from_slice(&claims_bytes).ok()?;
    if now_unix() > claims.expires_at {
        return None;
    }

    Some(claims)
}

fn validate_dashboard_app_token(token: &str, state: &AppState) -> Result<DashboardAppTokenClaims, String> {
    let verify_secrets = dashboard_token_verify_secrets(state);
    let mut claims = None;
    for secret in &verify_secrets {
        if let Some(c) = parse_dashboard_app_token(token, secret) {
            claims = Some(c);
            break;
        }
    }
    let claims = claims.ok_or_else(|| {
        "Token ist ungültig, abgelaufen oder Signatur fehlerhaft (kein Verify-Secret hat gepasst)".to_string()
    })?;

    let records = load_token_registry();
    let record = records
        .into_iter()
        .find(|r| r.token_id == claims.token_id)
        .ok_or_else(|| "Token-ID unbekannt".to_string())?;

    if record.revoked_at.is_some() {
        return Err("Token wurde widerrufen".to_string());
    }
    if record.app_id != claims.app_id {
        return Err("Token app_id stimmt nicht mit Registry überein".to_string());
    }
    if record.expires_at != claims.expires_at {
        return Err("Token-Laufzeit passt nicht zur Registry".to_string());
    }

    Ok(claims)
}

fn load_registry() -> Vec<WidgetRegistryEntry> {
    let path = registry_file();
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(entries) = serde_json::from_str::<Vec<WidgetRegistryEntry>>(&raw) {
            return entries;
        }
    }
    Vec::new()
}

fn save_registry(entries: &[WidgetRegistryEntry]) -> Result<(), String> {
    let path = registry_file();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
    std::fs::write(path, body).map_err(|e| e.to_string())
}

fn has_scope(scope: &str) -> bool {
    scope_catalog()
        .into_iter()
        .any(|s| s.scope == scope)
}

fn dashboard_require_app_id() -> bool {
    matches!(
        std::env::var("STONE_DASHBOARD_REQUIRE_APP_ID").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn dashboard_allow_remote_widgets() -> bool {
    match std::env::var("STONE_DASHBOARD_ALLOW_REMOTE_WIDGETS").as_deref() {
        Ok("0") | Ok("false") | Ok("no") => false,
        _ => true,
    }
}

fn allowed_widget_origins_from_env() -> std::collections::HashSet<String> {
    std::env::var("STONE_DASHBOARD_ALLOWED_WIDGET_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn app_origin(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    Some(parsed.origin().ascii_serialization())
}

fn is_local_origin(origin: &str) -> bool {
    origin.starts_with("http://127.0.0.1")
        || origin.starts_with("http://localhost")
        || origin.starts_with("http://[::1]")
}

fn validate_origin_policy(manifest: &DashboardManifest) -> Result<(), String> {
    let origin = app_origin(&manifest.entry_url)
        .ok_or_else(|| "entry_url konnte nicht als Origin geparst werden".to_string())?;

    if !dashboard_allow_remote_widgets() && !is_local_origin(&origin) {
        return Err(format!(
            "Remote Widgets sind deaktiviert: entry_url origin {origin} ist nicht lokal"
        ));
    }

    let allowlist = allowed_widget_origins_from_env();
    if !allowlist.is_empty() && !allowlist.contains(&origin) {
        return Err(format!(
            "entry_url origin {origin} ist nicht in STONE_DASHBOARD_ALLOWED_WIDGET_ORIGINS"
        ));
    }

    if !manifest.allowed_origins.is_empty() {
        for allowed in &manifest.allowed_origins {
            if !allowlist.is_empty() && !allowlist.contains(allowed) {
                return Err(format!(
                    "manifest allowed_origin {allowed} ist nicht in STONE_DASHBOARD_ALLOWED_WIDGET_ORIGINS"
                ));
            }
        }
    }

    Ok(())
}

fn normalize_granted_scopes(requested: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for scope in requested {
        let s = scope.trim();
        if s.is_empty() {
            continue;
        }
        if !has_scope(s) {
            return Err(format!("Unbekannter Scope: {s}"));
        }
        if seen.insert(s.to_string()) {
            out.push(s.to_string());
        }
    }
    Ok(out)
}

fn default_token_ttl_secs() -> u64 {
    let raw = std::env::var("STONE_DASHBOARD_TOKEN_TTL_SECS").unwrap_or_else(|_| "86400".to_string());
    let parsed = raw.trim().parse::<u64>().unwrap_or(86400);
    parsed.clamp(300, 60 * 60 * 24 * 30)
}

fn default_scopes() -> std::collections::HashSet<String> {
    scope_catalog()
        .into_iter()
        .filter(|s| s.default_granted)
        .map(|s| s.scope.to_string())
        .collect()
}

fn extra_scopes_from_env() -> std::collections::HashSet<String> {
    std::env::var("STONE_DASHBOARD_EXTRA_SCOPES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn effective_scopes_non_admin() -> std::collections::HashSet<String> {
    let mut scopes = default_scopes();
    scopes.extend(extra_scopes_from_env());
    scopes
}

fn require_scope(
    headers: &HeaderMap,
    state: &AppState,
    scope: &str,
    app_id: Option<&str>,
) -> Result<(), axum::response::Response> {
    if !has_scope(scope) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": format!("Unbekannter Scope: {scope}")})),
        ).into_response());
    }

    if require_admin(headers, state).is_ok() {
        return Ok(());
    }

    if let Some(bearer) = extract_bearer_token(headers) {
        if bearer.starts_with(&(DASHBOARD_TOKEN_PREFIX.to_string() + ".")) {
            let claims = match validate_dashboard_app_token(&bearer, state) {
                Ok(c) => c,
                Err(err) => {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        axum::Json(json!({"error": err})),
                    ).into_response())
                }
            };

            if let Some(app) = app_id {
                if app != claims.app_id {
                    return Err((
                        StatusCode::FORBIDDEN,
                        axum::Json(json!({
                            "error": "app_id passt nicht zum Dashboard-Token",
                            "token_app_id": claims.app_id,
                            "requested_app_id": app,
                        })),
                    ).into_response());
                }
            }

            let mut granted = default_scopes();
            granted.extend(claims.scopes.into_iter());
            if granted.contains(scope) {
                return Ok(());
            }
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "error": "Scope nicht erlaubt",
                    "required_scope": scope,
                    "app_id": claims.app_id,
                    "auth": "dashboard_token",
                })),
            ).into_response());
        }
    }

    let _user = require_user(headers, state)?;

    if dashboard_require_app_id() && app_id.is_none() {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "app_id erforderlich",
                "hint": "Sende ?app_id=<deine-app-id> oder deaktiviere STONE_DASHBOARD_REQUIRE_APP_ID",
            })),
        ).into_response());
    }

    let granted = if let Some(app) = app_id {
        let registry = load_registry();
        if let Some(entry) = registry.into_iter().find(|e| e.app_id == app) {
            let mut app_scopes = default_scopes();
            app_scopes.extend(entry.granted_scopes.into_iter());
            app_scopes
        } else {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "error": "Unbekannte app_id",
                    "app_id": app,
                })),
            ).into_response());
        }
    } else {
        effective_scopes_non_admin()
    };

    if granted.contains(scope) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "Scope nicht erlaubt",
                "required_scope": scope,
                "granted_scopes": granted,
            })),
        ).into_response())
    }
}

fn scope_catalog() -> Vec<ScopeDescriptor> {
    vec![
        ScopeDescriptor {
            scope: "dashboard:read",
            access: "read",
            description: "Darf Dashboard-Metadaten und Capabilities lesen",
            default_granted: true,
        },
        ScopeDescriptor {
            scope: "metrics:read",
            access: "read",
            description: "Darf Node-, Chain- und P2P-Metriken lesen",
            default_granted: true,
        },
        ScopeDescriptor {
            scope: "chat:read",
            access: "read",
            description: "Darf Chat-Statistiken und Chat-Index-Status lesen",
            default_granted: false,
        },
        ScopeDescriptor {
            scope: "mining:read",
            access: "read",
            description: "Darf Mining-Status und Reward-Infos lesen",
            default_granted: false,
        },
        ScopeDescriptor {
            scope: "node:write",
            access: "write",
            description: "Darf Node-Aktionen triggern (nur trusted Apps)",
            default_granted: false,
        },
        ScopeDescriptor {
            scope: "mining:write",
            access: "write",
            description: "Darf Mining-Aktionen triggern (Throttle, Withdraw)",
            default_granted: false,
        },
        ScopeDescriptor {
            scope: "admin:write",
            access: "admin",
            description: "Darf Admin-Endpunkte triggern",
            default_granted: false,
        },
    ]
}

fn validate_manifest(mut manifest: DashboardManifest) -> ManifestValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    manifest.app_id = manifest.app_id.trim().to_string();
    manifest.name = manifest.name.trim().to_string();
    manifest.version = manifest.version.trim().to_string();
    manifest.entry_url = manifest.entry_url.trim().to_string();

    if manifest.app_id.is_empty() {
        errors.push("app_id fehlt".to_string());
    }
    if manifest.name.is_empty() {
        errors.push("name fehlt".to_string());
    }
    if manifest.version.is_empty() {
        errors.push("version fehlt".to_string());
    }
    if manifest.entry_url.is_empty() {
        errors.push("entry_url fehlt".to_string());
    }

    if !(manifest.entry_url.starts_with("https://") || manifest.entry_url.starts_with("http://")) {
        errors.push("entry_url muss mit http:// oder https:// beginnen".to_string());
    }

    if manifest.supported_api_versions.is_empty() {
        warnings.push("supported_api_versions ist leer, fallback auf v2 only".to_string());
        manifest.supported_api_versions = vec!["v2".to_string()];
    }

    let known_scopes: std::collections::HashSet<&'static str> = scope_catalog()
        .into_iter()
        .map(|s| s.scope)
        .collect();

    for scope in &manifest.required_permissions {
        if !known_scopes.contains(scope.as_str()) {
            errors.push(format!("unbekannter scope: {scope}"));
        }
    }

    if manifest.required_permissions.is_empty() {
        warnings.push("required_permissions ist leer, App bleibt read-only minimal".to_string());
    }

    if manifest.default_layout.is_empty() {
        warnings.push("default_layout ist leer".to_string());
    }

    let valid = errors.is_empty();
    ManifestValidationResult {
        valid,
        errors,
        warnings,
        normalized: if valid { Some(manifest) } else { None },
    }
}

/// GET /api/v2/dashboard/capabilities
pub async fn handle_dashboard_v2_capabilities(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<AppScopeQuery>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "dashboard:read", query.app_id.as_deref()) {
        return e;
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "api_version": API_VERSION,
            "manifest_version": MANIFEST_VERSION,
            "node_id": state.node.node_id,
            "features": {
                "custom_dashboards": true,
                "widget_sandbox": true,
                "manifest_validation": true,
                "permissions": true,
                "app_tokens": true,
                "token_key_rotation": true,
                "hot_reload": false
            },
            "routes": {
                "capabilities": "/api/v2/dashboard/capabilities",
                "scopes": "/api/v2/dashboard/scopes",
                "manifest_schema": "/api/v2/dashboard/manifest/schema",
                "manifest_validate": "/api/v2/dashboard/manifest/validate",
                "tokens_list": "/api/v2/dashboard/tokens",
                "tokens_issue": "/api/v2/dashboard/tokens/issue",
                "tokens_revoke": "/api/v2/dashboard/tokens/{token_id}/revoke"
            }
        })),
    ).into_response()
}

/// GET /api/v2/dashboard/scopes
pub async fn handle_dashboard_v2_scopes(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<AppScopeQuery>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "dashboard:read", query.app_id.as_deref()) {
        return e;
    }

    (StatusCode::OK, axum::Json(json!({
        "api_version": API_VERSION,
        "scopes": scope_catalog(),
    }))).into_response()
}

/// GET /api/v2/dashboard/manifest/schema
pub async fn handle_dashboard_v2_manifest_schema(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<AppScopeQuery>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "dashboard:read", query.app_id.as_deref()) {
        return e;
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "manifest_version": MANIFEST_VERSION,
            "required": [
                "app_id",
                "name",
                "version",
                "entry_url"
            ],
            "fields": {
                "app_id": "string (stable unique id, e.g. com.acme.ops-dashboard)",
                "name": "string",
                "version": "string (semver empfohlen)",
                "entry_url": "string (http(s) url)",
                "description": "string",
                "author": "string",
                "required_permissions": "string[]",
                "supported_api_versions": "string[]",
                "allowed_origins": "string[]",
                "default_layout": "{widget_id, zone, min_w, min_h}[]"
            }
        })),
    ).into_response()
}

/// POST /api/v2/dashboard/manifest/validate
pub async fn handle_dashboard_v2_manifest_validate(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<AppScopeQuery>,
    axum::Json(manifest): axum::Json<DashboardManifest>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "dashboard:read", query.app_id.as_deref()) {
        return e;
    }

    let result = validate_manifest(manifest);
    let status = if result.valid {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, axum::Json(result)).into_response()
}

/// GET /api/v2/dashboard/widgets
pub async fn handle_dashboard_v2_widgets(
        headers: HeaderMap,
        State(state): State<AppState>,
    Query(query): Query<AppScopeQuery>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "dashboard:read", query.app_id.as_deref()) {
                return e;
        }

        let widgets = load_registry();
        (
                StatusCode::OK,
                axum::Json(json!({
                        "count": widgets.len(),
                        "widgets": widgets,
                })),
        ).into_response()
}

/// POST /api/v2/dashboard/widgets/install
pub async fn handle_dashboard_v2_widgets_install(
        headers: HeaderMap,
        State(state): State<AppState>,
        axum::Json(req): axum::Json<InstallWidgetRequest>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "admin:write", None) {
                return e;
        }

        let actor = match require_user(&headers, &state) {
                Ok(u) => u.name,
                Err(_) => "admin".to_string(),
        };

        let validation = validate_manifest(req.manifest);
        if !validation.valid {
                return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({
                                "ok": false,
                                "validation": validation,
                        })),
                ).into_response();
        }

        let normalized = validation.normalized.expect("normalized manifest for valid result");
        if let Err(err) = validate_origin_policy(&normalized) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"ok": false, "error": err})),
            ).into_response();
        }

        let requested_scopes = if req.grant_scopes.is_empty() {
            normalized.required_permissions.clone()
        } else {
            req.grant_scopes.clone()
        };

        let granted_scopes = match normalize_granted_scopes(&requested_scopes) {
            Ok(s) => s,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"ok": false, "error": err})),
                ).into_response();
            }
        };

        let mut entries = load_registry();
        entries.retain(|e| e.app_id != normalized.app_id);
        entries.push(WidgetRegistryEntry {
                app_id: normalized.app_id.clone(),
                manifest: normalized,
            granted_scopes,
                installed_at: Utc::now().timestamp(),
                installed_by: actor,
        });

        if let Err(err) = save_registry(&entries) {
                return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({"ok": false, "error": err})),
                ).into_response();
        }

            (
                StatusCode::OK,
                axum::Json(json!({
                        "ok": true,
                        "installed": entries.len(),
                })),
            ).into_response()
}

/// DELETE /api/v2/dashboard/widgets/{app_id}
pub async fn handle_dashboard_v2_widgets_remove(
        headers: HeaderMap,
        State(state): State<AppState>,
        Path(app_id): Path<String>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "admin:write", None) {
                return e;
        }

        let mut entries = load_registry();
        let before = entries.len();
        entries.retain(|e| e.app_id != app_id);

        if before == entries.len() {
                return (
                        StatusCode::NOT_FOUND,
                        axum::Json(json!({"ok": false, "error": "Widget nicht gefunden"})),
                ).into_response();
        }

        if let Err(err) = save_registry(&entries) {
                return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({"ok": false, "error": err})),
                ).into_response();
        }

            (StatusCode::OK, axum::Json(json!({"ok": true, "remaining": entries.len()}))).into_response()
}

/// POST /api/v2/dashboard/tokens/issue
pub async fn handle_dashboard_v2_tokens_issue(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<IssueDashboardTokenRequest>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "admin:write", None) {
        return e;
    }

    let actor = match require_user(&headers, &state) {
        Ok(u) => u.name,
        Err(_) => "admin".to_string(),
    };

    let app_id = req.app_id.trim().to_string();
    if app_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"ok": false, "error": "app_id fehlt"})),
        ).into_response();
    }

    let widgets = load_registry();
    let entry = match widgets.into_iter().find(|w| w.app_id == app_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"ok": false, "error": "App nicht installiert"})),
            ).into_response();
        }
    };

    let requested = if req.scopes.is_empty() {
        entry.granted_scopes.clone()
    } else {
        req.scopes.clone()
    };
    let normalized = match normalize_granted_scopes(&requested) {
        Ok(s) => s,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"ok": false, "error": err})),
            ).into_response();
        }
    };

    let mut allowed = default_scopes();
    allowed.extend(entry.granted_scopes.iter().cloned());
    for scope in &normalized {
        if !allowed.contains(scope) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "ok": false,
                    "error": format!("Scope {scope} ist nicht für diese App freigegeben"),
                })),
            ).into_response();
        }
    }

    let now = now_unix();
    let ttl = req.ttl_secs.unwrap_or_else(default_token_ttl_secs).clamp(300, 60 * 60 * 24 * 30);
    let token_id = format!("dtok_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let claims = DashboardAppTokenClaims {
        token_id: token_id.clone(),
        app_id: app_id.clone(),
        scopes: normalized.clone(),
        issued_at: now,
        expires_at: now + ttl,
    };
    let token = match generate_dashboard_app_token(&claims, &dashboard_token_signing_secret(&state)) {
        Ok(t) => t,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"ok": false, "error": err})),
            ).into_response();
        }
    };

    let mut records = load_token_registry();
    records.push(DashboardAppTokenRecord {
        token_id: token_id.clone(),
        app_id: app_id.clone(),
        scopes: normalized.clone(),
        issued_at: now,
        expires_at: now + ttl,
        issued_by: actor,
        label: req.label.trim().to_string(),
        revoked_at: None,
    });
    if let Err(err) = save_token_registry(&records) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"ok": false, "error": err})),
        ).into_response();
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "ok": true,
            "token_id": token_id,
            "app_id": app_id,
            "scopes": normalized,
            "expires_at": claims.expires_at,
            "token": token,
        })),
    ).into_response()
}

/// GET /api/v2/dashboard/tokens
pub async fn handle_dashboard_v2_tokens_list(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<DashboardTokenListQuery>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "admin:write", None) {
        return e;
    }

    let mut records = load_token_registry();
    if let Some(app_id) = query.app_id {
        records.retain(|r| r.app_id == app_id);
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "count": records.len(),
            "tokens": records,
        })),
    ).into_response()
}

/// POST /api/v2/dashboard/tokens/{token_id}/revoke
pub async fn handle_dashboard_v2_tokens_revoke(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(token_id): Path<String>,
) -> Response {
    if let Err(e) = require_scope(&headers, &state, "admin:write", None) {
        return e;
    }

    let mut records = load_token_registry();
    let now = now_unix();
    let mut found = false;
    for rec in &mut records {
        if rec.token_id == token_id {
            rec.revoked_at = Some(now);
            found = true;
            break;
        }
    }

    if !found {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"ok": false, "error": "Token nicht gefunden"})),
        ).into_response();
    }

    if let Err(err) = save_token_registry(&records) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"ok": false, "error": err})),
        ).into_response();
    }

    (StatusCode::OK, axum::Json(json!({"ok": true, "revoked_at": now}))).into_response()
}

/// GET /ui/dashboard-v2
pub async fn handle_dashboard_v2_shell() -> impl IntoResponse {
        let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Stone Dashboard v2 Shell</title>
    <style>
        :root{--bg:#0b1220;--panel:#111b2e;--ink:#dbe7ff;--muted:#8ea4d8;--line:#2a3a5d;--ok:#4ade80;--acc:#60a5fa}
        *{box-sizing:border-box} body{margin:0;font-family:ui-sans-serif,system-ui;background:radial-gradient(circle at 20% 0%,#14213d 0%,#0b1220 45%,#090f1d 100%);color:var(--ink)}
        .wrap{max-width:960px;margin:0 auto;padding:24px}
        .hero{display:flex;gap:12px;align-items:center;margin-bottom:16px}
        .chip{font-size:12px;color:#021229;background:linear-gradient(135deg,#7dd3fc,#93c5fd);padding:4px 10px;border-radius:999px;font-weight:700}
        .card{background:linear-gradient(180deg,rgba(17,27,46,.95),rgba(12,19,33,.95));border:1px solid var(--line);border-radius:14px;padding:16px;margin:12px 0}
        .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
        input{flex:1;min-width:260px;background:#0b1324;border:1px solid var(--line);border-radius:10px;padding:10px 12px;color:var(--ink)}
        button{border:1px solid #2c4c85;background:linear-gradient(135deg,#2f5fb6,#3b82f6);color:white;border-radius:10px;padding:10px 14px;cursor:pointer;font-weight:700}
        .hint{color:var(--muted);font-size:13px}
        .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
        .widget{border:1px solid #29406f;background:#0b162b;border-radius:12px;padding:12px}
        .widget h3{margin:0 0 6px 0;font-size:15px}
        .meta{font-size:12px;color:var(--muted)}
        .ok{color:var(--ok)}
    </style>
</head>
<body>
    <div class="wrap">
        <div class="hero">
            <span class="chip">Dashboard v2 Shell</span>
            <strong>Custom Widget Host</strong>
        </div>

        <div class="card">
            <div class="row">
                <input id="apiKey" placeholder="x-api-key or session token" />
                <input id="appId" placeholder="app_id (z.B. com.example.ops-dashboard)" />
                <button onclick="loadWidgets()">Load Widgets</button>
            </div>
            <p class="hint">This shell loads registered widgets from /api/v2/dashboard/widgets and can be used by teams as a starting point.</p>
            <p id="status" class="hint">Status: idle</p>
        </div>

        <div id="widgets" class="grid"></div>
    </div>
    <script>
        async function loadWidgets(){
            const token = document.getElementById('apiKey').value.trim();
            const appId = document.getElementById('appId').value.trim();
            const headers = {};
            if(token){
                if(token.startsWith('sd2.')){
                    headers['authorization'] = 'Bearer ' + token;
                } else {
                    headers['x-api-key'] = token;
                }
            }
            const status = document.getElementById('status');
            status.textContent = 'Status: loading...';
            try{
                const qs = appId ? ('?app_id=' + encodeURIComponent(appId)) : '';
                const resp = await fetch('/api/v2/dashboard/widgets' + qs,{headers});
                const data = await resp.json();
                if(!resp.ok){
                    status.textContent = 'Status: error ' + (data.error || resp.status);
                    return;
                }
                status.innerHTML = 'Status: <span class="ok">loaded</span> (' + data.count + ' widgets)';
                const root = document.getElementById('widgets');
                root.innerHTML = '';
                for(const w of data.widgets){
                    const el = document.createElement('div');
                    el.className = 'widget';
                    el.innerHTML = '<h3>' + w.manifest.name + '</h3>' +
                        '<div class="meta">app_id: ' + w.app_id + '</div>' +
                        '<div class="meta">entry: ' + w.manifest.entry_url + '</div>' +
                        '<div class="meta">version: ' + w.manifest.version + '</div>';
                    root.appendChild(el);
                }
            }catch(e){
                status.textContent = 'Status: network error';
            }
        }
    </script>
</body>
</html>"#;

        axum::response::Html(html)
}
