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

                let host_display = match &result.hostname {
                    Some(h) if h != &result.ip.to_string() => format!(" ({})", h),
                    _ => "".to_string(),
                };
                let banner_display = match &result.banner {
                    Some(b) => format!(" | Banner: {}", b),
                    None => "".to_string(),
                };
                let os_display = match &result.os {
                    Some(os) => format!(" | OS: {}", os),
                    None => "".to_string(),
                };

                println!(
                    "[+] {}{}:{} - OPEN{}{}",
                    result.ip, host_display, result.port, banner_display, os_display
                );
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
