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

            Some(ScanResult {
                ip,
                port,
                is_open: true,
                hostname,
                banner,
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
