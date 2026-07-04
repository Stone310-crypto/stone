use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Write};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut custom_url: Option<String> = None;
    let mut network = "testnet";
    let mut watch = false;
    let mut interval: u64 = 3;
    let mut trace_peer: Option<String> = None;
    let mut show_topology = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mainnet" => network = "mainnet",
            "--testnet" => network = "testnet",
            "--url" => { if let Some(u) = args.get(i+1) { custom_url = Some(u.clone()); i+=1; } }
            "--watch" | "-w" => watch = true,
            "--interval" => { if let Some(v) = args.get(i+1) { interval = v.parse().unwrap_or(3); i+=1; } }
            "--trace" => { if let Some(p) = args.get(i+1) { trace_peer = Some(p.clone()); i+=1; } }
            "--topology" => show_topology = true,
            "--help" | "-h" => {
                println!("stone-discover [--mainnet|--testnet] [--url URL]");
                println!("  --watch      Live monitoring");
                println!("  --trace PID  Trace a specific PeerId");
                println!("  --topology   Show network topology");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let base_url = custom_url.unwrap_or_else(|| {
        let port = if network == "mainnet" { "3180" } else { "3080" };
        format!("http://127.0.0.1:{port}")
    });

    if watch { run_watch(&base_url, network, interval).await; }
    else if let Some(ref pid) = trace_peer { trace_peer_id(&base_url, pid).await; }
    else if show_topology { show_topology_view(&base_url, network).await; }
    else { run_oneshot(&base_url, network).await; }
}

async fn fetch_json(url: &str) -> Value {
    let client = reqwest::Client::new();
    let resp = client.get(url).timeout(std::time::Duration::from_secs(5)).send().await;
    match resp {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(_) => Value::default(),
    }
}

async fn get_status(base: &str) -> Value { fetch_json(&format!("{base}/api/v1/status")).await }
async fn get_p2p(base: &str) -> Value { fetch_json(&format!("{base}/api/v1/p2p/status")).await }

fn b(s: &str) -> String { format!("\x1b[1m{s}\x1b[0m") }
fn c(s: &str) -> String { format!("\x1b[36m{s}\x1b[0m") }
fn g(s: &str) -> String { format!("\x1b[32m{s}\x1b[0m") }
fn y(s: &str) -> String { format!("\x1b[33m{s}\x1b[0m") }
fn r(s: &str) -> String { format!("\x1b[31m{s}\x1b[0m") }
fn d(s: &str) -> String { format!("\x1b[2m{s}\x1b[0m") }
fn m(s: &str) -> String { format!("\x1b[35m{s}\x1b[0m") }

async fn run_oneshot(base: &str, network: &str) {
    let status = get_status(base).await;
    let p2p = get_p2p(base).await;
    if status.get("setup_complete").is_none() { eprintln!("{}", r(&format!("Node nicht erreichbar: {base}"))); return; }

    println!("{}", b(&format!("Stone Peer Discovery — {network}")));
    println!("   {}", d(&format!("Node: {} | Chain: {}", status["node_name"].as_str().unwrap_or("?"), status["chain_id"].as_str().unwrap_or("?"))));
    show_peers(&p2p);
    show_metrics(&p2p);
}

async fn run_watch(base: &str, network: &str, interval: u64) {
    let mut prev_peers: HashMap<String, (u64, bool)> = HashMap::new();
    loop {
        print!("\x1b[2J\x1b[H");
        let p2p = get_p2p(base).await;
        let conn = p2p["connected_peers"].as_u64().unwrap_or(0);
        println!("{}  {}", b(&format!("Stone Peer Discovery — {network}")), d(&chrono::Local::now().format("%H:%M:%S").to_string()));
        println!("   {} connected  [Ctrl+C to exit]", g(&conn.to_string()));
        show_peers(&p2p);
        io::stdout().flush().ok();
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        let _ = prev_peers; // track changes would go here
    }
}

async fn trace_peer_id(base: &str, target: &str) {
    let p2p = get_p2p(base).await;
    println!("{}", b(&format!("Tracing Peer: {target}")));
    let peers = p2p["peers"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    for peer in peers {
        let pid = peer["peer_id"].as_str().unwrap_or("?");
        if !pid.starts_with(target) { continue; }
        println!("  PeerId:     {}", m(pid));
        println!("  Connected:  {}", if peer["connected"].as_bool().unwrap_or(false) { g("Yes") } else { r("No") });
        println!("  Agent:      {}", peer["agent_version"].as_str().unwrap_or("?"));
        println!("  Blocks Rx:  {}", peer["blocks_received"].as_u64().unwrap_or(0));
        if let Some(lat) = peer["avg_latency_ms"].as_u64() {
            println!("  Latency:    {}ms", if lat < 50 { g(&lat.to_string()) } else { y(&lat.to_string()) });
        }
        let addrs = peer["addresses"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        if !addrs.is_empty() {
            println!("  Addresses:");
            for addr in addrs {
                let a = addr.as_str().unwrap_or("?");
                let ip = a.split('/').find(|p| p.chars().all(|c| c.is_ascii_digit() || c == '.')).unwrap_or("?");
                println!("    {}  [IP: {}]", d(a), c(ip));
            }
        }
        if peer["blocks_received"].as_u64().unwrap_or(0) > 100 { println!("  Role: {}", c("Active Peer")); }
        else { println!("  Role: {}", d("Fresh Node")); }
        if peer["in_gossipsub_mesh"].as_bool().unwrap_or(false) { println!("  Mesh:  {}", g("In Gossipsub Mesh")); }
    }
    println!();
}

async fn show_topology_view(base: &str, network: &str) {
    let p2p = get_p2p(base).await;
    let local_pid = p2p["local_peer_id"].as_str().unwrap_or("?");
    println!("{}", b(&format!("Network Topology — {network}")));
    println!("   Local: {}", d(local_pid));
    println!("   Local Node");
    let peers = p2p["peers"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    for (i, peer) in peers.iter().enumerate() {
        let pid = peer["peer_id"].as_str().unwrap_or("?");
        let conn = peer["connected"].as_bool().unwrap_or(false);
        let blocks = peer["blocks_received"].as_u64().unwrap_or(0);
        let is_last = i == peers.len() - 1;
        let branch = if is_last { "   └─" } else { "   ├─" };
        let icon = if conn { "✅" } else { "❌" };
        let short = &pid[..pid.len().min(40)];
        println!("{branch} {icon} {short}  ({blocks} blocks)");
    }
    println!();
}

fn show_peers(p2p: &Value) {
    let peers = p2p["peers"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let conn = peers.iter().filter(|p| p["connected"].as_bool().unwrap_or(false)).count();
    println!("Peers ({} connected / {} total):", conn, peers.len());
    for (i, peer) in peers.iter().enumerate() {
        let pid = peer["peer_id"].as_str().unwrap_or("?");
        let short = &pid[..pid.len().min(44)];
        let icon = if peer["connected"].as_bool().unwrap_or(false) { "✅" } else { "❌" };
        let blocks = peer["blocks_received"].as_u64().unwrap_or(0);
        let lat = peer["avg_latency_ms"].as_u64().map(|l| format!("{l}ms")).unwrap_or_else(|| "-".into());
        let agent = peer["agent_version"].as_str().unwrap_or("-");
        let short_agent = &agent[..agent.len().min(24)];
        let mesh = if peer["in_gossipsub_mesh"].as_bool().unwrap_or(false) { " 📡" } else { "" };
        println!("  {i:>3} {icon} {short}  blk:{blocks:>5}  lat:{lat:>6}  {short_agent}{mesh}");
    }
    println!();
}

fn show_metrics(p2p: &Value) {
    if let Some(m) = p2p.get("metrics") {
        println!("Metrics:");
        println!("  Traffic In:   {} ({:.1} MiB)", fmt_bytes(m["bytes_in"].as_u64().unwrap_or(0)), m["bytes_in"].as_u64().unwrap_or(0) as f64 / 1_048_576.0);
        println!("  Traffic Out:  {} ({:.1} MiB)", fmt_bytes(m["bytes_out"].as_u64().unwrap_or(0)), m["bytes_out"].as_u64().unwrap_or(0) as f64 / 1_048_576.0);
        println!("  Msgs In/Out:  {} / {}", m["messages_in"].as_u64().unwrap_or(0), m["messages_out"].as_u64().unwrap_or(0));
        println!("  Uptime:       {}", fmt_secs(m["uptime_secs"].as_u64().unwrap_or(0)));
    }
}

fn fmt_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 { format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0) }
    else if bytes >= 1_048_576 { format!("{:.2} MiB", bytes as f64 / 1_048_576.0) }
    else if bytes >= 1024 { format!("{:.2} KiB", bytes as f64 / 1024.0) }
    else { format!("{bytes} B") }
}

fn fmt_secs(secs: u64) -> String {
    if secs >= 3600 { format!("{}h {}m", secs / 3600, (secs % 3600) / 60) }
    else if secs >= 60 { format!("{}m", secs / 60) }
    else { format!("{secs}s") }
}
