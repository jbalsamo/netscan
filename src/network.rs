use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

pub fn parse_subnet(cidr: &str) -> Result<Vec<IpAddr>, String> {
    let net = IpNet::from_str(cidr).map_err(|e| format!("Invalid CIDR subnet '{}': {}", cidr, e))?;

    let mut ips = Vec::new();
    match net {
        IpNet::V4(v4_net) => {
            let start = u32::from(v4_net.network());
            let end = u32::from(v4_net.broadcast());

            // For subnets /31 and /32, include all addresses (network/broadcast are valid hosts).
            // For larger subnets (e.g. /24), optionally skip network (.0) and broadcast (.255) if desired,
            // but including them or skipping network/broadcast: usually port scanners include all or skip network/broadcast.
            // Let's include all addresses in the range so /32, /31, and specific scans work seamlessly,
            // or if prefix < 31, skip network and broadcast.
            if v4_net.prefix_len() >= 31 {
                for ip_u32 in start..=end {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)));
                }
            } else {
                // Skip network and broadcast for subnets /30 and broader
                if start < end {
                    for ip_u32 in (start + 1)..end {
                        ips.push(IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)));
                    }
                } else {
                    ips.push(IpAddr::V4(v4_net.addr()));
                }
            }
        }
        IpNet::V6(v6_net) => {
            for ip in v6_net.hosts() {
                ips.push(IpAddr::V6(ip));
                if ips.len() > 65536 {
                    return Err("IPv6 subnet too large to scan entirely (>65536 hosts)".to_string());
                }
            }
            if ips.is_empty() {
                ips.push(IpAddr::V6(v6_net.addr()));
            }
        }
    }

    if ips.is_empty() {
        ips.push(net.addr());
    }

    Ok(ips)
}
