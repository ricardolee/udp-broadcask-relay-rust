#!/bin/bash
# tests/integration_test.sh
set -ex

# Ensure we are in the project root
cd "$(dirname "$0")/.."


# Define test runner
run_tests() {
    # Create temporary directory for test logs and outputs
    TEST_DIR=$(mktemp -d /tmp/udp-broadcast-relay-tests.XXXXXX)
    echo "Temporary test directory created: $TEST_DIR"

    # Make case files executable
    chmod +x tests/cases/*.sh

    # ----------------------------------------------------
    # Setup Virtual Ethernet Pairs & Networking
    # ----------------------------------------------------
    echo "Setting up veth pairs..."
    ip link add veth1 type veth peer name veth1-peer
    ip link add veth2 type veth peer name veth2-peer

    ip link set lo up
    ip link set veth1 up
    ip link set veth1-peer up
    ip link set veth2 up
    ip link set veth2-peer up

    ip addr add 192.168.10.1/24 dev veth1
    ip addr add 192.168.10.2/24 dev veth1-peer
    ip addr add 192.168.20.1/24 dev veth2
    ip addr add 192.168.20.2/24 dev veth2-peer

    # Manually populate ARP table inside the namespace to bypass ARP resolution failure between virtual ethernet peers
    MAC_VETH1=$(ip link show veth1 | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1)
    MAC_VETH1_PEER=$(ip link show veth1-peer | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1)
    MAC_VETH2=$(ip link show veth2 | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1)
    MAC_VETH2_PEER=$(ip link show veth2-peer | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1)

    ip neigh add 192.168.10.2 lladdr $MAC_VETH1_PEER dev veth1 || true
    ip neigh add 192.168.10.1 lladdr $MAC_VETH1 dev veth1-peer || true
    ip neigh add 192.168.20.2 lladdr $MAC_VETH2_PEER dev veth2 || true
    ip neigh add 192.168.20.1 lladdr $MAC_VETH2 dev veth2-peer || true

    # Disable Reverse Path Filtering (rp_filter) inside the namespace
    # to allow Standard UDP sockets to receive packets with virtual peer IPs.
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter || true
    echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter || true
    echo 0 > /proc/sys/net/ipv4/conf/veth1/rp_filter || true
    echo 0 > /proc/sys/net/ipv4/conf/veth1-peer/rp_filter || true
    echo 0 > /proc/sys/net/ipv4/conf/veth2/rp_filter || true
    echo 0 > /proc/sys/net/ipv4/conf/veth2-peer/rp_filter || true

    # Enable accept_local to allow unicast packets with local source IPs between veth interfaces in the same namespace
    echo 1 > /proc/sys/net/ipv4/conf/all/accept_local || true
    echo 1 > /proc/sys/net/ipv4/conf/default/accept_local || true
    echo 1 > /proc/sys/net/ipv4/conf/veth1/accept_local || true
    echo 1 > /proc/sys/net/ipv4/conf/veth1-peer/accept_local || true
    echo 1 > /proc/sys/net/ipv4/conf/veth2/accept_local || true
    echo 1 > /proc/sys/net/ipv4/conf/veth2-peer/accept_local || true

    # Enable routing/forwarding inside the namespace
    echo 1 > /proc/sys/net/ipv4/ip_forward || true

    # Execute modular test case scripts
    ./tests/cases/case_1_spoofing.sh "$TEST_DIR"
    ./tests/cases/case_2_cidr_acl.sh "$TEST_DIR"
    ./tests/cases/case_3_ttl_loop.sh "$TEST_DIR"
    ./tests/cases/case_4_ssdp_dial.sh "$TEST_DIR"

    # Cleanup temporary files and interfaces
    echo "Cleaning up..."
    rm -rf "$TEST_DIR"
    ip link del veth1 || true
    ip link del veth2 || true
    echo "ALL TESTS PASSED!"
}

# Export the function so unshare can see it, or just run the commands
if [ "$1" == "--inside-ns" ]; then
    run_tests
else
    unshare -rn "$0" --inside-ns
fi
