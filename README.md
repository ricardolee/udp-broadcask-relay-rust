# UDP Broadcast & Multicast Relay (Rust)

A Rust implementation of a UDP broadcast and multicast relay, featuring loop prevention, CIDR ACLs, and dynamic SSDP/DIAL service proxying.

## Features

- **POSIX Control Messages**: Uses standard kernel-space UDP sockets (`SOCK_DGRAM`) with POSIX control messages (`IP_PKTINFO`, `IP_RECVTTL`, and `IP_RECVTOS` via `recvmsg`) to extract packet metadata such as the incoming interface index, TTL, and ToS.
- **SSDP / M-SEARCH / DIAL Dynamic Proxying (`--msearch`)**: Intercepts SSDP queries, dynamically routes search responses, starts client-facing TCP description proxies, and rewrites HTTP Location/Application-URL streams to bridge media players and streaming devices across subnets.
- **Longest Prefix Match CIDR ACLs**: Evaluates `--allow-cidr` and `--block-cidr` rules by netmask length in descending order to determine matching priority.
- **IP Spoofing Modes (`-s`)**: 
  - Literal IP: Replaces the source IP with a specified IP.
  - `1.1.1.1` (Chromecast Mode): Replaces the source IP with the outgoing interface's IP and the source port with the target destination port.
  - `1.1.1.2`: Replaces the source IP with the outgoing interface's IP and keeps the original source port.
- **Loop Prevention Mechanisms**:
  - DSCP/ToS Loop Prevention: Marks outgoing packets with a DSCP ID and discards incoming packets with matching DSCP.
  - TTL-based Loop Prevention (`-t`): Modifies the outgoing TTL to `ID + 64` and discards incoming packets matching this signature.
  - Specific Instance Blocking (`--blockid`): Discards packets matching specified other instance IDs.
- **Dynamic Multicast**: Joins multicast groups on participating interfaces.

## Requirements

- **OS**: Linux (requires `bind_device` / `SO_BINDTODEVICE` support).
- **Privileges**: Root privileges or capabilities (`CAP_NET_RAW` and `CAP_NET_ADMIN`).

## Command Line Arguments

- `-id, --id <1-63>`: Unique ID for the instance, used in loop prevention DSCP/TTL tagging.
- `-p, --port <PORT>`: UDP port to listen on and relay.
- `-d, --dev <IFACE>`: Network interface to include in the relay (specify at least twice, e.g. `-d eth0 -d eth1`).
- `-m, --multicast <ADDR>`: Multicast group to join on participating interfaces (e.g. `239.255.255.250`).
- `--allow-cidr <CIDR>`: Allow source IP ranges (evaluated using longest prefix match).
- `--block-cidr <CIDR>`: Block source IP ranges (evaluated using longest prefix match).
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
sudo udp-broadcast-relay-rust --id 1 --port 5353 --dev eth0 --dev eth1 --multicast 224.0.0.251
```

### Relay SSDP (port 1900) with dynamic DIAL/SSDP proxying and TTL loop prevention
```bash
sudo udp-broadcast-relay-rust --id 2 --port 1900 --dev eth0 --dev eth1 --multicast 239.255.255.250 -t --msearch dial
```

### Relay on port 5555 with CIDR filtering and Chromecast spoofing
```bash
sudo udp-broadcast-relay-rust --id 5 --port 5555 --dev eth0 --dev eth1 --allow-cidr 192.168.1.0/24 --block-cidr 192.168.1.100/32 -s 1.1.1.1
```

## Compilation & Testing

### Build
To compile the release binary:
```bash
cargo build --release
```

### Run Integration Tests
The integration test suite executes inside an isolated network namespace. All temporary logs and files are automatically cleaned up.

```bash
# 1. Compile the project
cargo build

# 2. Run the tests (must be run as root to configure veth interfaces and namespaces)
sudo integration_test.sh
```
