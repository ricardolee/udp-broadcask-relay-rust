# UDP Broadcast & Multicast Relay (Rust)

A high-performance Rust implementation of a production-grade UDP broadcast and multicast relay, featuring advanced loop prevention, CIDR ACLs, and dynamic SSDP/DIAL service proxying.

## Features

- **High Performance & Low Overhead**: Uses standard kernel-space UDP sockets (`SOCK_DGRAM`) with POSIX control messages (`IP_PKTINFO`, `IP_RECVTTL`, and `IP_RECVTOS` via `recvmsg`) instead of heavy datalink Ethernet packet sniffing, ensuring minimal CPU usage and high packet throughput.
- **SSDP / M-SEARCH / DIAL Dynamic Proxying (`--msearch`)**: Intercepts SSDP queries, dynamically routes search responses, spins up client-facing TCP description proxies, and rewrites HTTP Location/Application-URL streams on the fly to bridge smart TVs, media players, and streaming devices across subnets.
- **Longest Prefix Match CIDR ACLs**: Supports combining arbitrary `--allow-cidr` and `--block-cidr` rules, automatically ordering and evaluating them by netmask length descending to guarantee specific matching priority.
- **Smart IP Spoofing (`-s`)**: 
  - Literal IP: Replaces source IP with a literal IP.
  - `1.1.1.1` (Chromecast Mode): Replaces source IP with the outgoing interface's IP and source port with the target destination port.
  - `1.1.1.2`: Replaces source IP with the outgoing interface's IP and keeps the original source port.
- **Robust Loop Prevention**:
  - DSCP/ToS Loop Prevention: Marks outgoing packets with a custom DSCP ID and discards incoming packets with matching DSCP.
  - TTL-based Loop Prevention (`-t`): Modifies the outgoing TTL to `ID + 64` and discards incoming packets matching this signature.
  - Specific Instance Blocking (`--blockid`): Discards packets tagged with other specified instance IDs.
- **Dynamic Multicast**: Dynamically joins multicast groups on participating interfaces.

## Requirements

- **OS**: Linux (requires `SO_BINDTODEVICE` socket bindings).
- **Privileges**: Root privileges or capabilities (`CAP_NET_RAW` and `CAP_NET_ADMIN`).

## Command Line Arguments

- `-id, --id <1-63>`: Unique ID for the instance, used in loop prevention DSCP/TTL tagging.
- `-p, --port <PORT>`: UDP port to listen on and relay.
- `-d, --dev <IFACE>`: Network interface to include in the relay (specify at least twice, e.g. `-d eth0 -d eth1`).
- `-m, --multicast <ADDR>`: Multicast group to join on participating interfaces (e.g. `239.255.255.250`).
- `--allow-cidr <CIDR>`: Statically allow source IP ranges (evaluated using longest prefix match).
- `--block-cidr <CIDR>`: Statically block source IP ranges (evaluated using longest prefix match).
- `-s, --spoof <IP_OR_TOKEN>`: Spoof source IP/port on relayed packets. Supports literal IPs and special tokens `1.1.1.1` and `1.1.1.2`.
- `-t, --ttl-id`: Use TTL-based loop prevention (`ID + 64`) instead of DSCP/ToS loop prevention.
- `--blockid <ID>`: Discard packets tagged with specific other relay instance IDs.
- `--msearch <action>[,<search_string>]`: Enable SSDP M-SEARCH response processing.
  - Supported actions: `fwd`, `block`, `proxy`, `dial`.
  - Format example: `--msearch dial` or `--msearch proxy,urn:schemas-upnp-org:device:MediaRenderer:1`.
- `-v, --debug`: Increase logging verbosity (use multiple times for trace level, e.g. `-vv`).

## Usage Examples

### Relay mDNS (port 5353) between eth0 and eth1 using DSCP ID 1
```bash
sudo ./target/debug/udp-broadcast-relay-rust --id 1 --port 5353 --dev eth0 --dev eth1 --multicast 224.0.0.251
```

### Relay SSDP (port 1900) with dynamic DIAL/SSDP proxying and TTL loop prevention
```bash
sudo ./target/debug/udp-broadcast-relay-rust --id 2 --port 1900 --dev eth0 --dev eth1 --multicast 239.255.255.250 -t --msearch dial
```

### Relay on port 5555 with CIDR filtering and Chromecast spoofing
```bash
sudo ./target/debug/udp-broadcast-relay-rust --id 5 --port 5555 --dev eth0 --dev eth1 --allow-cidr 192.168.1.0/24 --block-cidr 192.168.1.100/32 -s 1.1.1.1
```

## Compilation & Testing

### Build
To compile the release binary:
```bash
cargo build --release
```

### Run Integration Tests
We have a fully modular, decoupled integration test suite that executes inside an isolated network namespace. All temporary logs and files are created inside `/tmp` and automatically cleaned up.

```bash
# 1. Compile the project
cargo build

# 2. Run the tests (must be run as root to configure veth interfaces and namespaces)
sudo ./tests/integration_test.sh
```
