# UDP Broadcast Relay (Rust)

A Rust implementation of a UDP broadcast/multicast relay, inspired by [udpbroadcastrelay](https://github.com/marjohn56/udpbroadcastrelay).

## Features
- Relays UDP broadcast and multicast packets between multiple interfaces.
- Forges source IP address to match the original sender (spoofing).
- Prevents loops using DSCP marking (customizable ID).
- Supports CIDR-based filtering (allow/block).
- Joins multicast groups on participating interfaces.

## Requirements
- Linux (uses `SO_BINDTODEVICE` and `AF_PACKET`).
- Root privileges or `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.

## Usage
```bash
# Relay mDNS (port 5353) between eth0 and eth1 with ID 1
sudo ./target/release/udp-broadcast-relay-rust --id 1 --port 5353 --dev eth0 --dev eth1 --multicast 224.0.0.251

# Relay SSDP (port 1900)
sudo ./target/release/udp-broadcast-relay-rust --id 2 --port 1900 --dev eth0 --dev eth1 --multicast 239.255.255.250
```

## Command Line Arguments
- `-id, --id <1-63>`: Unique ID for the instance, used for DSCP marking.
- `-p, --port <PORT>`: UDP port to relay.
- `-d, --dev <IFACE>`: Interface to include (specify at least twice).
- `-m, --multicast <ADDR>`: Multicast group to join.
- `--allow-cidr <CIDR>`: Only relay packets from these source networks.
- `--block-cidr <CIDR>`: Do not relay packets from these source networks.
- `-s, --spoof <IP>`: Force a specific source IP for relayed packets.
- `-v, --debug`: Increase logging verbosity.
