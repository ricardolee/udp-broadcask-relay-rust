#!/bin/bash
# tests/cases/case_1_spoofing.sh
set -e

TEST_DIR=$1
echo "============================================="
echo "Test Case 1: Core Relay & Smart Spoofing"
echo "============================================="

# Start relay with -s 1.1.1.1 (Chromecast mode)
./target/debug/udp-broadcast-relay-rust --id 1 --port 5555 --dev veth1 --dev veth2 -s 1.1.1.1 -vv > "$TEST_DIR/relay_t1.log" 2>&1 &
RELAY_PID=$!
sleep 1

rm -f "$TEST_DIR/received_t1.txt"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('192.168.20.255', 5555))
s.settimeout(3)
try:
    data, addr = s.recvfrom(1024)
    print(f'T1 RECEIVED: {data} from {addr}')
    with open('$TEST_DIR/received_t1.txt', 'w') as f:
        f.write(f'{data.decode()},{addr[0]},{addr[1]}')
except socket.timeout:
    print('T1 timeout')
" &
PY_PID=$!
sleep 0.5

# Send a broadcast from veth1-peer
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(('192.168.10.2', 4444))
s.sendto(b'HELLO-T1', ('192.168.10.255', 5555))
"
wait $PY_PID || true
kill $RELAY_PID || true
wait $RELAY_PID || true

if [ -f "$TEST_DIR/received_t1.txt" ]; then
    VAL=$(cat "$TEST_DIR/received_t1.txt")
    echo "T1 Output: $VAL"
    if [[ "$VAL" == "HELLO-T1,192.168.20.1,5555" ]]; then
        echo "SUCCESS: Test Case 1 Spoofing 1.1.1.1 worked!"
    else
        echo "FAILURE: Test Case 1 Spoofing 1.1.1.1 mismatch."
        exit 1
    fi
else
    echo "FAILURE: Test Case 1 packet not relayed."
    echo "Relay Log:"
    cat "$TEST_DIR/relay_t1.log"
    exit 1
fi
