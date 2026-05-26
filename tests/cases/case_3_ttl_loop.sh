#!/bin/bash
# tests/cases/case_3_ttl_loop.sh
set -e

TEST_DIR=$1
echo "============================================="
echo "Test Case 3: TTL-based Loop Prevention"
echo "============================================="

# Start with -t (TTL loop prevention) and block ID 10
./target/debug/udp-broadcast-relay-rust --id 5 --port 5555 --dev veth1 --dev veth2 -t --blockid 10 -vv > "$TEST_DIR/relay_t3.log" 2>&1 &
RELAY_PID=$!
sleep 1

# Verify standard packet is relayed
rm -f "$TEST_DIR/received_t3_std.txt"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('192.168.20.255', 5555))
s.settimeout(2)
try:
    data, addr = s.recvfrom(1024)
    with open('$TEST_DIR/received_t3_std.txt', 'w') as f:
        f.write(data.decode())
except socket.timeout:
    pass
" &
PY_PID=$!
sleep 0.5
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
s.bind(('192.168.10.2', 0))
s.sendto(b'STD-TTL', ('192.168.10.255', 5555))
"
wait $PY_PID || true

# Verify loop packet (TTL = ID + 64 = 69) is blocked
rm -f "$TEST_DIR/received_t3_loop.txt"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('192.168.20.255', 5555))
s.settimeout(2)
try:
    data, addr = s.recvfrom(1024)
    with open('$TEST_DIR/received_t3_loop.txt', 'w') as f:
        f.write(data.decode())
except socket.timeout:
    pass
" &
PY_PID=$!
sleep 0.5
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_IP, socket.IP_TTL, 69)
s.bind(('192.168.10.2', 0))
s.sendto(b'LOOP-TTL', ('192.168.10.255', 5555))
"
wait $PY_PID || true

# Verify blocked ID packet (TTL = 10 + 64 = 74) is blocked
rm -f "$TEST_DIR/received_t3_bid.txt"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('192.168.20.255', 5555))
s.settimeout(2)
try:
    data, addr = s.recvfrom(1024)
    with open('$TEST_DIR/received_t3_bid.txt', 'w') as f:
        f.write(data.decode())
except socket.timeout:
    pass
" &
PY_PID=$!
sleep 0.5
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_IP, socket.IP_TTL, 74)
s.bind(('192.168.10.2', 0))
s.sendto(b'BLOCK-ID-TTL', ('192.168.10.255', 5555))
"
wait $PY_PID || true

kill $RELAY_PID || true
wait $RELAY_PID || true

if [ -f "$TEST_DIR/received_t3_std.txt" ] && [ ! -f "$TEST_DIR/received_t3_loop.txt" ] && [ ! -f "$TEST_DIR/received_t3_bid.txt" ]; then
    echo "SUCCESS: Test Case 3 (TTL-based loop prevention & Block ID) worked!"
else
    echo "FAILURE: Test Case 3 failed. Std: $(cat "$TEST_DIR/received_t3_std.txt" 2>/dev/null), Loop: $(cat "$TEST_DIR/received_t3_loop.txt" 2>/dev/null), BlockID: $(cat "$TEST_DIR/received_t3_bid.txt" 2>/dev/null)"
    exit 1
fi
