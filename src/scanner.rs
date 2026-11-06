use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub is_open: bool,
    pub hostname: Option<String>,
    pub banner: Option<String>,
    pub os: Option<String>,
}

pub async fn scan_port(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    semaphore: Arc<Semaphore>,
) -> Option<ScanResult> {
    let _permit = semaphore.acquire().await.ok()?;
    let socket_addr = SocketAddr::new(ip, port);

    match timeout(timeout_duration, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            let banner = grab_banner(&mut stream, port).await;
            let hostname = crate::network::lookup_hostname(ip).await;
            let os = estimate_os(port, banner.as_deref(), &stream);

            Some(ScanResult {
                ip,
                port,
                is_open: true,
                hostname,
                banner,
                os,
            })
        }
        _ => None,
    }
}

async fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<String> {
    let banner_timeout = Duration::from_millis(200);
    let mut buf = vec![0u8; 512];

    // 1. Try reading first (services that speak first, e.g., SSH, FTP, SMTP)
    if let Ok(Ok(n)) = timeout(banner_timeout, stream.read(&mut buf)).await {
        if n > 0 {
            if let Ok(s) = String::from_utf8(buf[..n].to_vec()) {
                let cleaned = clean_banner(&s);
                if !cleaned.is_empty() {
                    return Some(cleaned);
                }
            }
        }
    }

    // 2. If nothing read, for common HTTP/web ports or generally, send a probe
    let probe: &[u8] = if port == 80 || port == 443 || port == 8080 || port == 8443 {
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    } else {
        b"\r\n"
    };

    if stream.write_all(probe).await.is_ok() {
        let mut buf2 = vec![0u8; 512];
        if let Ok(Ok(n)) = timeout(banner_timeout, stream.read(&mut buf2)).await {
            if n > 0 {
                if let Ok(s) = String::from_utf8(buf2[..n].to_vec()) {
                    let cleaned = clean_banner(&s);
                    if !cleaned.is_empty() {
                        return Some(cleaned);
                    }
                }
            }
        }
    }

    None
}

fn clean_banner(s: &str) -> String {
    s.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or(s)
        .chars()
        .filter(|c| !c.is_control() || *c == ' ' || *c == '\t')
        .collect::<String>()
        .trim()
        .chars()
        .take(120)
        .collect()
}

pub fn estimate_os(port: u16, banner: Option<&str>, _stream: &TcpStream) -> Option<String> {
    if let Some(b) = banner {
        let b_lower = b.to_lowercase();
        if b_lower.contains("windows") || b_lower.contains("microsoft") || b_lower.contains("iis") {
            return Some("Windows".to_string());
        }
        if b_lower.contains("ubuntu") || b_lower.contains("debian") || b_lower.contains("centos")
           || b_lower.contains("redhat") || b_lower.contains("linux") || b_lower.contains("openssh") {
            return Some("Linux / Unix".to_string());
        }
        if b_lower.contains("macos") || b_lower.contains("darwin") || b_lower.contains("apple") {
            return Some("macOS / Apple".to_string());
        }
    }

    match port {
        3389 | 445 | 135 | 139 => Some("Windows".to_string()),
        22 | 80 | 443 | 21 | 25 => Some("Linux / Unix / Server".to_string()),
        548 | 631 => Some("macOS / Unix".to_string()),
        _ => None,
    }
}
