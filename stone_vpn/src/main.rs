//! StoneVPN — Mesh Overlay Network für StoneChain
//!
//! ## Architektur
//!
//! ```text
//! ┌──────────────┐         ┌──────────────┐
//! │ Client A     │◄───────►│ Relay (VPS)  │
//! │ 10.1.0.2     │   UDP   │ 10.1.0.1     │
//! │ (Starlink)   │  Tunnel │ (öffentlich)  │
//! └──────────────┘         └──────┬───────┘
//!                                 │
//!                          ┌──────┴───────┐
//!                          │ Client B     │
//!                          │ 10.1.0.3     │
//!                          │ (öffentlich)  │
//!                          └──────────────┘
//! ```
//!
//! ## Wire-Format (UDP)
//!
//! Jedes Paket: `[1 byte type] [32 bytes sender_pubkey] [encrypted payload]`
//!
//! - Type 0x01: Handshake (X25519 ECDH → VPN-IP Zuweisung)
//! - Type 0x02: Data (ChaCha20Poly1305)
//! - Type 0x03: Keepalive (hält NAT-Mapping offen)
//! - Type 0x04: Route-Announce

mod ip_pool;
mod crypto;
mod peer;
mod tunnel;
mod tun_device;

use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(name = "stonevpn", version = "0.1.0")]
struct Args {
    #[arg(long, default_value = "10.1.0.0/24")]
    ip_pool: String,

    #[arg(long, default_value = "51821")]
    port: u16,

    /// Diese Node ist ein Relay (hat öffentliche IP)
    #[arg(long)]
    relay: bool,

    /// Relay-Nodes (host:port), kommagetrennt
    #[arg(long, default_value = "")]
    relays: String,

    /// Stone-Datenverzeichnis (default: ./stone_data)
    #[arg(long, default_value = "./stone_data")]
    stone_data: String,

    /// TUN-Device aktivieren (braucht sudo/admin)
    #[arg(long)]
    tun: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    println!("╔══════════════════════════════════════════╗");
    println!("║   StoneVPN — Mesh Overlay Network       ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║ IP-Pool: {: <30} ║", args.ip_pool);
    println!("║ Port:    {: <30} ║", args.port);
    println!("║ Modus:   {: <30} ║", if args.relay { "RELAY" } else { "CLIENT" });
    println!("╚══════════════════════════════════════════╝");

    // Relay: IP-Forwarding + NAT aktivieren
    if args.relay {
        tun_device::TunDevice::enable_ip_forwarding();
    }

    let pool = ip_pool::IpPool::new(&args.ip_pool)?;
    println!("🌐 Pool: {}/24 ({} IPs)", pool.network(), pool.available());

    let keypair = crypto::Keypair::load_or_create(&args.stone_data)
        .map_err(|e| format!("Keypair: {e}"))?;
    println!("🔑 Pubkey: {}", hex::encode(keypair.public_bytes()));

    let socket = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", args.port)).await?;
    println!("📡 UDP: 0.0.0.0:{}", args.port);

    let relay_addrs: Vec<SocketAddr> = args.relays.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let stone_data_path = std::path::PathBuf::from(&args.stone_data);
    let registry = peer::PeerRegistry::new(keypair, pool, relay_addrs, args.relay, stone_data_path.clone());
    let config = tunnel::TunnelConfig { stone_data: stone_data_path, enable_tun: args.tun };
    tunnel::run(socket, registry, config).await?;

    Ok(())
}
