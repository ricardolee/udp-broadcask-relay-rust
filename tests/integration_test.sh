#!/bin/bash
# tests/integration_test.sh
set -ex

# Ensure we are in the project root
cd "$(dirname "$0")/.."

if [ -z "$SKIP_BUILD" ]; then
    echo "Building project..."
    cargo build
fi


echo "Setting up network interfaces in unshared namespace..."
# Note: If running inside a container with CAP_NET_ADMIN, we can just use 'ip' directly.
# If running on host, we use 'unshare -rn' to avoid root requirements.

run_test() {
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

    echo "Starting relay..."
    ./target/debug/udp-broadcast-relay-rust --id 1 --port 5555 --dev veth1 --dev veth2 -vv > relay.log 2>&1 &
    RELAY_PID=$!
    sleep 2

    if ! kill -0 $RELAY_PID; then
        echo "Relay failed to start. Log:"
        cat relay.log
        exit 1
    fi

    echo "Testing broadcast relay..."
    rm -f received.txt
    # Listen on 0.0.0.0 because the relayed packet might be seen as broadcast on the target interface
    python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5555))
s.settimeout(5)
try:
    data, addr = s.recvfrom(1024)
    print(f"Received from {addr}")
    with open("received.txt", "wb") as f:
        f.write(data)
except socket.timeout:
    print("Timeout waiting for packet")
' &
    PY_LISTEN_PID=$!
    sleep 1

    python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("192.168.10.2", 0))
s.sendto(b"HELLO-INTEGRATION", ("255.255.255.255", 5555))
'
    wait $PY_LISTEN_PID || true

    if [ -f received.txt ] && grep -q "HELLO-INTEGRATION" received.txt; then
        echo "SUCCESS: Broadcast packet relayed!"
    else
        echo "FAILURE: Broadcast packet NOT relayed."
        echo "Relay log:"
        cat relay.log
        # If the log shows "Sending packet out of veth2", the relay did its job.
        # The network stack in unshare might be tricky with raw sockets and veth.
        if grep -q "Sending packet out of veth2" relay.log; then
            echo "Relay confirmed sending packet, but listener did not receive it."
            echo "This might be due to unprivileged unshare network limitations."
            echo "Since the relay logic is verified by the logs, we will consider it a partial success."
        fi
        exit 1
    fi

    echo "Testing loop prevention..."
    rm -f loop_received.txt
    python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("192.168.20.2", 5555))
s.settimeout(2)
try:
    data, addr = s.recvfrom(1024)
    with open("loop_received.txt", "wb") as f:
        f.write(data)
except socket.timeout:
    pass
' &
    PY_LP_PID=$!
    sleep 1

    python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_IP, socket.IP_TOS, 1 << 2)
s.bind(("192.168.10.2", 0))
s.sendto(b"LOOP-TEST", ("255.255.255.255", 5555))
'
    sleep 2
    # kill $LP_NC_PID || true # No longer needed as python script exits on timeout
    
    if [ -s loop_received.txt ]; then
        echo "FAILURE: Packet with DSCP 1 was relayed!"
        exit 1
    else
        echo "SUCCESS: Loop prevention worked."
    fi

    kill $RELAY_PID || true
    echo "All tests passed!"
    # Cleanup temporary files
    rm -f received.txt loop_received.txt relay.log
}

# Export the function so unshare can see it, or just run the commands
if [ "$1" == "--inside-ns" ]; then
    run_test
else
    unshare -rn "$0" --inside-ns
fi
