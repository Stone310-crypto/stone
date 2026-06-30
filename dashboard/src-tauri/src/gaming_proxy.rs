//! Gaming-Proxy: Tauri-Commands, die das Stone-Node-Backend aufrufen.

use serde::{Deserialize, Serialize};

/// Basis-URL der Stone-Node.
fn node_url() -> String {
    std::env::var("STONE_NODE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3080".into())
}

/// API-Key für die Node.
fn node_api_key() -> String {
    std::env::var("STONE_API_KEY")
        .unwrap_or_else(|_| String::new())
}

// ─── Typen ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct CompanyInfo {
    pub owner_wallet: String,
    pub name: String,
    pub country: String,
    pub website: String,
    pub verified: bool,
    pub status: String,
    pub registered_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GameInfo {
    pub game_id: String,
    pub owner_company: String,
    pub name: String,
    pub version: String,
    pub genres: Vec<String>,
    pub verified: bool,
    pub status: String,
    pub registered_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCompanyRequest {
    pub owner_wallet: String,
    pub name: String,
    pub country: String,
    pub website: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterGameRequest {
    pub game_id: String,
    pub owner_company: String,
    pub name: String,
    pub version: String,
    pub genres: Vec<String>,
}

// ─── HTTP-Proxy ─────────────────────────────────────────────────────────────

async fn api_get<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let url = format!("{}{}", node_url(), path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Client-Fehler: {e}"))?;

    let resp = client
        .get(&url)
        .header("x-api-key", node_api_key())
        .send()
        .await
        .map_err(|e| format!("Node nicht erreichbar: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON-Fehler: {e}"))?;

    serde_json::from_value(body)
        .map_err(|e| format!("Deserialisierung: {e}"))
}

async fn api_post<T: Serialize, R: for<'de> Deserialize<'de>>(path: &str, body: &T) -> Result<R, String> {
    let url = format!("{}{}", node_url(), path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("Client-Fehler: {e}"))?;

    let resp = client
        .post(&url)
        .header("x-api-key", node_api_key())
        .json(body)
        .send()
        .await
        .map_err(|e| format!("Node nicht erreichbar: {e}"))?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                body.as_str().unwrap_or("Unbekannter Fehler")
            });
        return Err(format!("HTTP {}: {msg}", status.as_u16()));
    }

    serde_json::from_value(body).map_err(|e| format!("Deserialisierung: {e}"))
}

// ─── Transaction-Builder ────────────────────────────────────────────────────

/// Baut eine signierte Self-TX für Game-Chain-Operationen.
/// Erfordert den API-Key der Node für Server-seitiges Signing.
async fn submit_game_chain_tx(
    tx_type: &str,
    from_wallet: &str,
    data: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // Game-Chain erwartet signierte TokenTx im Format:
    // { tx: { tx_type, from, to, signature, data, ... } }
    let tx = serde_json::json!({
        "tx": {
            "tx_type": tx_type,
            "from": from_wallet,
            "to": from_wallet,       // Self-TX
            "data": data,
            "chain_id": "stone-testnet",
            "timestamp": chrono::Utc::now().timestamp(),
            "nonce": 0,               // Vom Ledger aufgelöst
            "signature": "",
            "signer": from_wallet,
        }
    });

    api_post("/api/v1/game-chain/submit", &tx).await
}

// ─── Tauri Commands ──────────────────────────────────────────────────────────

/// Listet alle registrierten Firmen auf.
#[tauri::command]
pub async fn list_companies() -> Result<Vec<CompanyInfo>, String> {
    let resp: serde_json::Value = api_get("/api/v1/companies").await?;
    let companies = resp
        .get("companies")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    serde_json::from_value(serde_json::Value::Array(companies))
        .map_err(|e| format!("{e}"))
}

/// Erstellt eine neue Firma (Company).
#[tauri::command]
pub async fn create_company(req: CreateCompanyRequest) -> Result<CompanyInfo, String> {
    let data = serde_json::json!({
        "name": req.name,
        "country": req.country,
        "website": req.website,
    });
    let resp: serde_json::Value = submit_game_chain_tx("CompanyRegister", &req.owner_wallet, data).await?;
    serde_json::from_value(resp).map_err(|e| format!("{e}"))
}

/// Listet alle registrierten Spiele auf.
#[tauri::command]
pub async fn list_games() -> Result<Vec<GameInfo>, String> {
    let resp: serde_json::Value = api_get("/api/v1/games/verified").await?;
    let games = resp
        .get("games")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    serde_json::from_value(serde_json::Value::Array(games))
        .map_err(|e| format!("{e}"))
}

/// Registriert ein neues Spiel unter einer Firma.
#[tauri::command]
pub async fn register_game(req: RegisterGameRequest) -> Result<GameInfo, String> {
    let data = serde_json::json!({
        "game_id": req.game_id,
        "name": req.name,
        "version": req.version,
        "genres": req.genres,
    });
    let resp: serde_json::Value = submit_game_chain_tx("GameRegister", &req.owner_company, data).await?;
    serde_json::from_value(resp).map_err(|e| format!("{e}"))
}

/// Gibt die Spiele einer bestimmten Firma zurück.
#[tauri::command]
pub async fn company_games(owner_wallet: String) -> Result<Vec<GameInfo>, String> {
    let resp: serde_json::Value = api_get(&format!("/api/v1/companies/{}/games", owner_wallet)).await?;
    let games = resp
        .get("games")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    serde_json::from_value(serde_json::Value::Array(games))
        .map_err(|e| format!("{e}"))
}

/// Prüft ob eine Game-ID bereits vergeben ist.
#[tauri::command]
pub async fn check_game_id(game_id: String) -> Result<bool, String> {
    match api_get::<serde_json::Value>(&format!("/api/v1/games/{}", game_id)).await {
        Ok(v) => Ok(v.get("game_id").is_some()),
        Err(_) => Ok(false), // Nicht gefunden = verfügbar
    }
}
