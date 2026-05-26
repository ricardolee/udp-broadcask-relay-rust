#!/bin/bash
# tests/cases/case_4_ssdp_dial.sh
set -e

TEST_DIR=$1
echo "============================================="
echo "Test Case 4: SSDP / M-SEARCH / DIAL Proxying"
echo "============================================="

# Start relay with SSDP/DIAL dynamic proxying on port 1900 and join SSDP multicast group
./target/debug/udp-broadcast-relay-rust --id 1 --port 1900 --dev veth1 --dev veth2 \
    --msearch dial --multicast 239.255.255.250 -vv > "$TEST_DIR/relay_t4.log" 2>&1 &
RELAY_PID=$!
sleep 1

# Spin up mock SSDP Target Server
python3 -c "
import socket
import threading
import time

# Mock TCP DIAL server
def run_tcp_server():
    ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ts.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ts.bind(('192.168.20.2', 8080))
    ts.listen(5)
    print('Mock TCP DIAL Server listening on port 8080')
    try:
        conn, addr = ts.accept()
        print('Mock TCP got connection from', addr)
        req = conn.recv(4096)
        print('Mock TCP req:', req)
        
        # Respond with Application-URL pointing to another endpoint
        resp = b'HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nApplication-URL: http://192.168.20.2:8080/apps/\r\nContent-Length: 10\r\n\r\nDIALDEVICE'
        conn.sendall(resp)
        conn.close()
    except Exception as e:
        print('Mock TCP server error:', e)
    finally:
        ts.close()

threading.Thread(target=run_tcp_server, daemon=True).start()

# UDP SSDP Server
us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
us.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
us.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
us.bind(('192.168.20.255', 1900))
us.settimeout(5)
try:
    data, addr = us.recvfrom(2048)
    print(f'Mock UDP Server received: {data} from {addr}')
    if b'M-SEARCH' in data:
        resp = b'HTTP/1.1 200 OK\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nLOCATION: http://192.168.20.2:8080/dd.xml\r\n\r\n'
        us.sendto(resp, addr)
        print('Mock UDP Server replied to', addr)
        time.sleep(5)
except socket.timeout:
    print('Mock UDP Server timeout waiting for M-SEARCH')
finally:
    us.close()
" &
MOCK_SRV_PID=$!
sleep 0.5

# Start L2 raw packet sniffer
python3 -c "
import socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
s.bind(('veth1-peer', 0))
s.settimeout(8)
print('Sniffer started on veth1-peer')
try:
    while True:
        pkt, addr = s.recvfrom(65535)
        if len(pkt) >= 42:
            sport = int.from_bytes(pkt[34:36], 'big')
            dport = int.from_bytes(pkt[36:38], 'big')
            if sport == 19000 or dport == 19000 or sport == 1900 or dport == 1900 or b'M-SEARCH' in pkt or b'Location' in pkt or b'LOCATION' in pkt:
                print(f'SNIFFED: len={len(pkt)} sport={sport} dport={dport} payload={pkt[42:]}')
except socket.timeout:
    print('Sniffer timeout')
except Exception as e:
    print('Sniffer error:', e)
" &
SNIFFER_PID=$!
sleep 0.5

# Run the SSDP Client
rm -f "$TEST_DIR/received_t4.txt"
python3 -c "
import socket
import time
import urllib.request

# Client UDP Socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
c.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
c.bind(('192.168.10.2', 19000))
c.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('192.168.10.2'))
c.settimeout(4)

msearch_req = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n'
c.sendto(msearch_req, ('192.168.10.255', 1900))
print('Client sent M-SEARCH request')

try:
    data, addr = c.recvfrom(2048)
    print('Client received response:', data)
    
    # Parse LOCATION
    location = None
    for line in data.decode().split('\r\n'):
        if line.lower().startswith('location:'):
            location = line.split(':', 1)[1].strip()
            break
            
    print('Extracted LOCATION:', location)
    if location and '192.168.10.1' in location:
        # Fetch the device description via TCP proxy
        print('Connecting to TCP proxy Location URL:', location)
        req = urllib.request.Request(location)
        with urllib.request.urlopen(req, timeout=3) as response:
            body = response.read().decode()
            headers = response.info()
            app_url = headers.get('Application-URL')
            print('Proxy response headers:', headers)
            print('Proxy response body:', body)
            with open('$TEST_DIR/received_t4.txt', 'w') as f:
                f.write(f'OK,{location},{app_url}')
except Exception as e:
    print('Client error:', e)
finally:
    c.close()
" &
CLIENT_PID=$!

sleep 5
kill $RELAY_PID || true
wait $RELAY_PID || true

if [ -f "$TEST_DIR/received_t4.txt" ]; then
    VAL=$(cat "$TEST_DIR/received_t4.txt")
    echo "T4 Result: $VAL"
    if [[ "$VAL" == OK,http://192.168.10.1:* ]]; then
        echo "SUCCESS: Test Case 4 SSDP & DIAL dynamic proxying worked!"
    else
        echo "FAILURE: Test Case 4 values mismatch."
        exit 1
    fi
else
    echo "FAILURE: Test Case 4 SSDP & DIAL dynamic proxying failed to receive or rewrite."
    echo "Relay Log:"
    cat "$TEST_DIR/relay_t4.log"
    exit 1
fi
