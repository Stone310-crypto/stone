//! VPN-Tunnel — Integrierter UDP-VPN für Sync hinter NAT.
//!
//! ## Architektur
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  stone-master                                   │
//! │  ┌──────────┐  ┌──────────────┐  ┌───────────┐ │
//! │  │ SwarmTask│  │ REST Sync    │  │ VpnTunnel │ │
//! │  │ (libp2p) │  │ pull_from_   │  │ (UDP VPN) │ │
//! │  │          │  │ peer()       │  │           │ │
//! │  └──────────┘  └──────┬───────┘  └─────┬─────┘ │
//! │                       │                │        │
//! │    Sync-Fallback:     │                │        │
//! │    pull_from_peer() ──┴── Direkt HTTP   │        │
//! │         │                               │        │
//! │         └── Fehler ──▶ VpnTunnel        │        │
//! │                        .http_get()      │        │
//! │                        (Proxy über UDP)  │        │
//! └─────────────────────────────────────────┴────────┘
//! ```
//!
//! ## Konfiguration (ENV)
//!
//! | Variable | Default | Beschreibung |
//! |----------|---------|--------------|
//! | `STONE_VPN_ENABLED` | `1` | VPN-Tunnel aktivieren |
//! | `STONE_VPN_SERVER_PORT` | `0` | UDP-Port für Server-Modus (0 = Client) |
//! | `STONE_VPN_SERVER_ADDR` | - | Server-Adresse (Client-Modus, z.B. `1.2.3.4:51822`) |
//! | `STONE_VPN_PSK` | - | Pre-Shared Key für Auth (32+ Zeichen empfohlen) |
//! | `STONE_VPN_SUBNET` | `10.1.0.0/24` | Subnetz für VPN-IPs |
//! | `STONE_VPN_CLIENT_ID` | - | Client-ID (VPN-ID, 8-stellig hex) |

pub mod crypto;
pub mod ip_pool;
pub mod peer;
pub mod proxy;
pub mod tunnel;

pub use tunnel::{VpnTunnel, VpnTunnelHandle, TunnelConfig, ProxyHttpResult};
