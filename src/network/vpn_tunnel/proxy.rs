//! HTTP-Proxy-Protokoll für den VPN-Tunnel.
//!
//! Ermöglicht HTTP-Requests durch den VPN-Tunnel zu tunneln —
//! perfekt für `pull_from_peer()` Sync über VPN.
//!
//! ## Pakettypen (kompatibel mit Stone-VPN `stonevpn-core`)
//! - TYPE_PROXY_REQ (0x15): Client→Server, HTTP-Anfrage
//! - TYPE_PROXY_RES (0x16): Server→Client, HTTP-Antwort
//!
//! ## Wire-Format (TYPE_PROXY_REQ)
//! ```text
//! [4B request_id BE] [2B url_len BE] [url UTF-8]
//! [1B method] [1B ct_len] [content_type UTF-8]
//! [2B extra_headers_len BE] [extra_headers UTF-8]
//! [4B body_len BE] [body]
//! ```
//!
//! ## Wire-Format (TYPE_PROXY_RES)
//! ```text
//! [4B request_id BE] [2B status BE]
//! [2B chunk_index BE] [2B total_chunks BE]
//! [4B body_len BE] [body]
//! ```

pub const TYPE_PROXY_REQ: u8 = 0x15;
pub const TYPE_PROXY_RES: u8 = 0x16;

/// HTTP-Methoden (für kompakte Kodierung).
pub mod method {
    pub const GET: u8 = 0;
    pub const POST: u8 = 1;
    pub const PUT: u8 = 2;
    pub const DELETE: u8 = 3;

    pub fn from_str(s: &str) -> u8 {
        match s.to_uppercase().as_str() {
            "GET" => GET,
            "POST" => POST,
            "PUT" => PUT,
            "DELETE" => DELETE,
            _ => GET,
        }
    }

    pub fn to_str(m: u8) -> &'static str {
        match m {
            GET => "GET",
            POST => "POST",
            PUT => "PUT",
            DELETE => "DELETE",
            _ => "GET",
        }
    }
}

/// HTTP-Proxy-Anfrage (Client → Server via VPN).
#[derive(Debug, Clone)]
pub struct ProxyRequest {
    pub request_id: u32,
    pub url: String,
    pub method: u8,
    pub content_type: String,
    pub extra_headers: String,
    pub body: Vec<u8>,
}

/// HTTP-Proxy-Antwort (Server → Client via VPN).
/// Unterstützt Chunking für große Antworten (> 60 KB pro Chunk).
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    pub request_id: u32,
    pub status: u16,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub body: Vec<u8>,
}

/// Maximale Chunk-Größe (8000 Bytes — Stone-VPN kompatibel, passt in UDP-Paket).
/// Multi-Chunk-Antworten können bei UDP-Reordering Nonce-Probleme verursachen.
pub const MAX_CHUNK_BODY: usize = 8000;

impl ProxyRequest {
    pub fn encode(&self) -> Vec<u8> {
        let url_bytes = self.url.as_bytes();
        let ct_bytes = self.content_type.as_bytes();
        let eh_bytes = self.extra_headers.as_bytes();
        let mut buf = Vec::with_capacity(
            4 + 2 + url_bytes.len() + 1 + 1 + ct_bytes.len() + 2 + eh_bytes.len() + 4 + self.body.len(),
        );
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&(url_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(url_bytes);
        buf.push(self.method);
        buf.push(ct_bytes.len() as u8);
        buf.extend_from_slice(ct_bytes);
        buf.extend_from_slice(&(eh_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(eh_bytes);
        buf.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let request_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let url_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let pos = 6 + url_len;
        if data.len() < pos + 4 {
            return None;
        }
        let url = String::from_utf8_lossy(&data[6..6 + url_len]).to_string();
        let method = data[pos];
        let ct_len = data[pos + 1] as usize;
        let ct_start = pos + 2;
        if data.len() < ct_start + ct_len + 2 {
            return None;
        }
        let content_type = String::from_utf8_lossy(&data[ct_start..ct_start + ct_len]).to_string();
        let eh_len_start = ct_start + ct_len;
        let eh_len = u16::from_be_bytes([data[eh_len_start], data[eh_len_start + 1]]) as usize;
        let eh_start = eh_len_start + 2;
        if data.len() < eh_start + eh_len + 4 {
            return None;
        }
        let extra_headers = String::from_utf8_lossy(&data[eh_start..eh_start + eh_len]).to_string();
        let body_len_start = eh_start + eh_len;
        let body_len =
            u32::from_be_bytes([data[body_len_start], data[body_len_start + 1], data[body_len_start + 2], data[body_len_start + 3]]) as usize;
        let body_start = body_len_start + 4;
        if data.len() < body_start + body_len {
            return None;
        }
        let body = data[body_start..body_start + body_len].to_vec();
        Some(ProxyRequest {
            request_id,
            url,
            method,
            content_type,
            extra_headers,
            body,
        })
    }

    /// Erstellt eine GET-Anfrage (einfachster Fall).
    pub fn get(request_id: u32, url: &str) -> Self {
        ProxyRequest {
            request_id,
            url: url.to_string(),
            method: method::GET,
            content_type: String::new(),
            extra_headers: String::new(),
            body: Vec::new(),
        }
    }

    /// Erstellt eine POST-Anfrage mit JSON-Body.
    pub fn post_json(request_id: u32, url: &str, body: Vec<u8>) -> Self {
        ProxyRequest {
            request_id,
            url: url.to_string(),
            method: method::POST,
            content_type: "application/json".into(),
            extra_headers: String::new(),
            body,
        }
    }
}

impl ProxyResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 2 + 2 + 2 + 4 + self.body.len());
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&self.status.to_be_bytes());
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());
        buf.extend_from_slice(&self.total_chunks.to_be_bytes());
        buf.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        let request_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let status = u16::from_be_bytes([data[4], data[5]]);
        let chunk_index = u16::from_be_bytes([data[6], data[7]]);
        let total_chunks = u16::from_be_bytes([data[8], data[9]]);
        let body_len = u32::from_be_bytes([data[10], data[11], data[12], data[13]]) as usize;
        if data.len() < 14 + body_len {
            return None;
        }
        let body = data[14..14 + body_len].to_vec();
        Some(ProxyResponse {
            request_id,
            status,
            chunk_index,
            total_chunks,
            body,
        })
    }
}
