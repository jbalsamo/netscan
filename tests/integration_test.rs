use netscan::cli::parse_ports;
use netscan::network::parse_subnet;
use netscan::scanner::scan_port;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[test]
fn test_parse_ports_valid() {
    let result = parse_ports("22, 80, 443, 8000-8002");
    assert!(result.is_ok());
    let ports = result.unwrap();
    assert_eq!(ports, vec![22, 80, 443, 8000, 8001, 8002]);
}

#[test]
fn test_parse_ports_invalid() {
    let result = parse_ports("22, invalid, 80");
    assert!(result.is_err());
}

#[test]
fn test_parse_subnet_v4_single() {
    let result = parse_subnet("127.0.0.1/32");
    assert!(result.is_ok());
    let ips = result.unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0].to_string(), "127.0.0.1");
}

#[tokio::test]
async fn test_scanner_closed_port() {
    // Port 1 is typically closed or filtered on localhost
    let ip = "127.0.0.1".parse().unwrap();
    let semaphore = Arc::new(Semaphore::new(10));
    let timeout = Duration::from_millis(100);

    let res = scan_port(ip, 1, timeout, semaphore).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn test_scanner_open_port() {
    // Start a temporary TCP listener on an ephemeral port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    let ip = addr.ip();
    let semaphore = Arc::new(Semaphore::new(10));
    let timeout = Duration::from_millis(500);

    let handle = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let res = scan_port(ip, port, timeout, semaphore).await;
    assert!(res.is_some());
    let scan_result = res.unwrap();
    assert!(scan_result.is_open);
    assert_eq!(scan_result.port, port);

    let _ = handle.await;
}
