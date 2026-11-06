use clap::Parser;
use netscan::cli::{parse_ports, Cli};
use netscan::network::parse_subnet;
use netscan::scanner::{scan_port, scan_udp_port, ScanResult};

use rand::seq::SliceRandom;
use rand::Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    let ips = parse_subnet(&args.target)?;
    let ports = parse_ports(&args.ports)?;

    let scan_tcp = args.protocol == "tcp" || args.protocol == "both";
    let scan_udp = args.protocol == "udp" || args.protocol == "both";

    if args.format == "text" {
        println!(
            "[*] Starting netscan on {} hosts across {} ports [Protocol: {}, Randomize: {}, Jitter: {}ms, Timeout: {}ms, Concurrency: {}]",
            ips.len(),
            ports.len(),
            args.protocol,
            args.randomize,
            args.jitter,
            args.timeout,
            args.concurrency
        );
    }

    let timeout_duration = Duration::from_millis(args.timeout);
    let semaphore = Arc::new(Semaphore::new(args.concurrency));

    let start_time = Instant::now();

    let mut scan_tasks = Vec::new();
    for ip in &ips {
        let ip = *ip;
        for &port in &ports {
            if scan_tcp {
                scan_tasks.push((ip, port, "TCP"));
            }
            if scan_udp {
                scan_tasks.push((ip, port, "UDP"));
            }
        }
    }

    if args.randomize {
        let mut rng = rand::thread_rng();
        scan_tasks.shuffle(&mut rng);
    }

    let mut set = tokio::task::JoinSet::new();

    for (ip, port, proto) in scan_tasks {
        let sem = Arc::clone(&semaphore);
        let timeout_dur = timeout_duration;
        let jitter = args.jitter;

        set.spawn(async move {
            if jitter > 0 {
                let sleep_ms = rand::thread_rng().gen_range(0..=jitter);
                if sleep_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                }
            }

            if proto == "TCP" {
                scan_port(ip, port, timeout_dur, sem).await
            } else {
                scan_udp_port(ip, port, timeout_dur, sem).await
            }
        });
    }

    let mut results: Vec<ScanResult> = Vec::new();
    let mut discovered_hosts = std::collections::HashSet::new();

    while let Some(res) = set.join_next().await {
        if let Ok(Some(result)) = res {
            if result.is_open {
                discovered_hosts.insert(result.ip);

                if args.format == "text" {
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
                        "[+] {}{}:{} [{}] - OPEN{}{}",
                        result.ip, host_display, result.port, result.protocol, banner_display, os_display
                    );
                }

                results.push(result);
            }
        }
    }

    let elapsed = start_time.elapsed();

    if args.format == "json" {
        let json_output = serde_json::to_string_pretty(&results)?;
        println!("{}", json_output);
    } else if args.format == "csv" {
        println!("ip,port,protocol,is_open,hostname,banner,os");
        for r in &results {
            println!(
                "{},{},{},{},\"{}\",\"{}\",\"{}\"",
                r.ip,
                r.port,
                r.protocol,
                r.is_open,
                r.hostname.as_deref().unwrap_or(""),
                r.banner.as_deref().unwrap_or(""),
                r.os.as_deref().unwrap_or("")
            );
        }
    } else {
        println!(
            "\n[*] Scan completed in {:.2?}. Found {} open port(s) across {} live host(s).",
            elapsed, results.len(), discovered_hosts.len()
        );
    }

    Ok(())
}
