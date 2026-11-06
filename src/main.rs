use clap::Parser;
use netscan::cli::{parse_ports, Cli};
use netscan::network::parse_subnet;
use netscan::scanner::scan_port;

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    let ips = parse_subnet(&args.target)?;
    let ports = parse_ports(&args.ports)?;

    println!(
        "[*] Starting netscan on {} hosts across {} ports (Timeout: {}ms, Concurrency: {})",
        ips.len(),
        ports.len(),
        args.timeout,
        args.concurrency
    );

    let timeout_duration = Duration::from_millis(args.timeout);
    let semaphore = Arc::new(Semaphore::new(args.concurrency));

    let start_time = Instant::now();

    let mut set = tokio::task::JoinSet::new();

    for ip in &ips {
        for &port in &ports {
            let ip = *ip;
            let sem = Arc::clone(&semaphore);
            let timeout_dur = timeout_duration;
            set.spawn(async move {
                scan_port(ip, port, timeout_dur, sem).await
            });
        }
    }

    let mut open_ports_count = 0;
    let mut discovered_hosts = std::collections::HashSet::new();

    while let Some(res) = set.join_next().await {
        if let Ok(Some(result)) = res {
            if result.is_open {
                open_ports_count += 1;
                discovered_hosts.insert(result.ip);
                println!("[+] {}:{} - OPEN", result.ip, result.port);
            }
        }
    }

    let elapsed = start_time.elapsed();

    println!(
        "\n[*] Scan completed in {:.2?}. Found {} open port(s) across {} live host(s).",
        elapsed, open_ports_count, discovered_hosts.len()
    );

    Ok(())
}
