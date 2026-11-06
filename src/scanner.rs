use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub is_open: bool,
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
        Ok(Ok(_stream)) => Some(ScanResult {
            ip,
            port,
            is_open: true,
        }),
        _ => None,
    }
}
