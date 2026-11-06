use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "netscan", author, version, about = "Fast async local network port scanner", long_about = None)]
pub struct Cli {
    /// Target CIDR subnet (e.g., 192.168.1.0/24 or 127.0.0.1/32)
    pub target: String,

    /// Ports to scan (comma-separated list, e.g., 22,80,443)
    #[arg(short, long, default_value = "21,22,23,25,53,80,110,443,445,3306,3389,8080")]
    pub ports: String,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value_t = 500)]
    pub timeout: u64,

    /// Maximum concurrent TCP connection attempts
    #[arg(short, long, default_value_t = 1000)]
    pub concurrency: usize,
}

pub fn parse_ports(ports_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in ports_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        } else if let Ok((start, end)) = parse_port_range(part) {
            for p in start..=end {
                ports.push(p);
            }
        } else {
            return Err(format!("Invalid port or port range: '{}'", part));
        }
    }
    if ports.is_empty() {
        return Err("No valid ports specified".to_string());
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_port_range(s: &str) -> Result<(u16, u16), ()> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() == 2 {
        let start = parts[0].trim().parse::<u16>().map_err(|_| ())?;
        let end = parts[1].trim().parse::<u16>().map_err(|_| ())?;
        if start <= end {
            return Ok((start, end));
        }
    }
    Err(())
}
