#!/bin/bash
# tests/cases/case_2_cidr_acl.sh
set -e

TEST_DIR=$1
echo "============================================="
echo "Test Case 2: CIDR ACL Longest Prefix Match"
echo "============================================="

./target/debug/udp-broadcast-relay-rust --id 1 --port 5555 --dev veth1 --dev veth2 \
    --allow-cidr 192.168.10.0/24 --block-cidr 192.168.10.100/32 -vv > "$TEST_DIR/relay_t2.log" 2>&1 &
RELAY_PID=$!
sleep 1

# Verify 192.168.10.2 is allowed
rm -f "$TEST_DIR/received_t2_allow.txt"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('192.168.20.255', 5555))
s.settimeout(2)
try:
    data, addr = s.recvfrom(1024)
    with open('$TEST_DIR/received_t2_allow.txt', 'w') as f:
        f.write(data.decode())
except socket.timeout:
    pass
" &
PY_PID=$!
sleep 0.5
ip addr add 192.168.10.2/24 dev veth1-peer || true
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(('192.168.10.2', 0))
s.sendto(b'ALLOW-TEST', ('192.168.10.255', 5555))
"
wait $PY_PID || true

# Verify 192.168.10.100 is blocked
rm -f "$TEST_DIR/received_t2_block.txt"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('192.168.20.255', 5555))
s.settimeout(2)
try:
    data, addr = s.recvfrom(1024)
    with open('$TEST_DIR/received_t2_block.txt', 'w') as f:
        f.write(data.decode())
except socket.timeout:
    pass
" &
PY_PID=$!
sleep 0.5
ip addr add 192.168.10.100/24 dev veth1-peer || true
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(('192.168.10.100', 0))
s.sendto(b'BLOCK-TEST', ('192.168.10.255', 5555))
"
wait $PY_PID || true
kill $RELAY_PID || true
wait $RELAY_PID || true
ip addr del 192.168.10.100/24 dev veth1-peer || true

if [ -f "$TEST_DIR/received_t2_allow.txt" ] && [ ! -f "$TEST_DIR/received_t2_block.txt" ]; then
    echo "SUCCESS: Test Case 2 (Longest Prefix Match block in allow) worked!"
else
    echo "FAILURE: Test Case 2 failed. Allow: $(cat "$TEST_DIR/received_t2_allow.txt" 2>/dev/null), Blocked was received: $(cat "$TEST_DIR/received_t2_block.txt" 2>/dev/null)"
    exit 1
fi
