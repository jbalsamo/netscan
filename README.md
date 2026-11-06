# netscan 🦀

A blazing fast, asynchronous local network port scanner built in Rust. `netscan` performs high-performance subnet scanning with reverse DNS lookup, service banner grabbing, OS fingerprinting, stealth randomization/jitter, and multiple output formats (Text, JSON, CSV).

---

## Features

- **Subnet CIDR Scanning**: Scan IPv4/IPv6 subnets seamlessly (e.g., `192.168.1.0/24`, `127.0.0.1/32`).
- **TCP & UDP Port Scanning**: Scan TCP ports, UDP ports, or both with protocol-specific lightweight probes.
- **Reverse DNS Resolution**: Automatically resolves IP addresses to hostnames.
- **Service Banner Grabbing**: Captures initial connection banners and HTTP/protocol responses.
- **OS Fingerprinting**: Heuristic operating system detection based on banners, port profiles, and network signatures.
- **Stealth Options**: Randomized port/target shuffling and adjustable millisecond timing jitter to evade signature-based detection and rate limiting.
- **Flexible Output Formats**: Human-readable text, machine-readable JSON, or CSV for reporting and automation.
- **High Concurrency & Rate Limiting**: Asynchronous tokio engine with tunable concurrency semaphores and timeouts.

---

## Installation

Ensure you have Rust (edition 2021+) installed:

```bash
git clone https://github.com/jbalsamo/netscan.git
cd netscan
cargo build --release
```

The compiled binary will be available at `target/release/netscan`.

---

## Usage

```bash
netscan <TARGET> [OPTIONS]
```

### Options

| Option | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--ports` | `-p` | Common ports | Ports or port ranges (e.g., `22,80,443,8000-8010`) |
| `--timeout` | `-t` | `500` | Connection timeout in milliseconds |
| `--concurrency` | `-c` | `1000` | Maximum concurrent connection attempts |
| `--format` | `-f` | `text` | Output format (`text`, `json`, `csv`) |
| `--protocol` | `-P` | `tcp` | Protocol to scan (`tcp`, `udp`, `both`) |
| `--randomize` | - | `false` | Shuffle scan order (Stealth mode) |
| `--jitter` | - | `0` | Random delay jitter in ms between requests (Stealth mode) |

---

## Examples

### 1. Basic TCP Scan
```bash
cargo run --release -- 127.0.0.1/32 --ports 22,80,443
```

### 2. Stealth Scan with Port Randomization and Timing Jitter
```bash
cargo run --release -- 192.168.1.0/24 --ports 1-1024 --randomize --jitter 50
```

### 3. Export Results as JSON
```bash
cargo run --release -- 192.168.1.0/24 --ports 21,22,80,443 --format json
```

---

## Testing

Run unit and integration tests:

```bash
cargo test
```

---

## License

MIT License.
