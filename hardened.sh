#!/usr/bin/env bash
# Tests for keep-alive hardening: hard caps + drip-proof timer + leftover buffering.
set -u
cd "$(dirname "$0")"
pkill -9 picoweb 2>/dev/null || true
sleep 0.3
./picoweb 8080 ./wwwroot 2 100 > /tmp/m.log 2>&1 &
SVR=$!
sleep 0.5
echo "=== STARTUP ==="
cat /tmp/m.log
echo
echo "=== leftover bytes buffered (write 2 reqs in one chunk; expect 2 x 200) ==="
{
    printf 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    printf 'GET /css/style.css HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
} | timeout 2 nc -q2 127.0.0.1 8080 | grep -c '^HTTP/1.1 200'
echo
echo "=== leftover bytes buffered (write 3 reqs in one chunk; expect 3 x 200) ==="
{
    printf 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    printf 'GET /css/style.css HTTP/1.1\r\nHost: localhost\r\n\r\n'
    printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
} | timeout 2 nc -q2 127.0.0.1 8080 | grep -c '^HTTP/1.1 200'
echo
echo "=== max-requests cap (curl reuses while it can; cap=100 forces reconnect) ==="
URLS=""
for i in $(seq 1 250); do URLS="$URLS http://127.0.0.1:8080/"; done
RES=$(curl --silent -o /dev/null -w "%{response_code} %{num_connects}\n" \
    -H "Host: localhost" $URLS)
NEW_CONNS=$(echo "$RES" | awk '{s += $2} END{print s}')
ALL_OK=$(echo "$RES" | awk '$1 == 200 {n++} END{print n}')
echo "  total reqs=$(echo "$RES" | wc -l)  ok_count=$ALL_OK  new_conns_made=$NEW_CONNS"
echo "  ^-- expect 250 reqs, all 200, ~3 new conns (250/100 ≈ 3)"
echo
echo "=== Connection: close as token list ==="
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, close\r\n\r\n' | \
    timeout 1 nc -q1 127.0.0.1 8080 | grep -i '^connection:'
echo
echo "=== slowloris (drip ~1 byte/sec; expect kill at idle_ms=10s) ==="
START=$(date +%s)
( for c in G E T ' ' '/' ' ' H T T P; do printf '%s' "$c"; sleep 1.5; done; sleep 5 ) | \
    timeout 30 nc -q1 127.0.0.1 8080 > /tmp/slow.out 2>&1
END=$(date +%s)
DUR=$((END - START))
BYTES=$(wc -c < /tmp/slow.out)
echo "  drip closed after ${DUR}s; bytes received from server=${BYTES}"
echo "  ^-- expect ~10s, 0 bytes (server killed conn before headers complete)"
echo
echo "=== short bench (uncapped; new server) ==="
kill -9 $SVR; sleep 0.3
./picoweb 8080 ./wwwroot 2 0 > /tmp/m2.log 2>&1 &
SVR=$!
sleep 0.5
./bench 8080 64 10 / localhost
echo
echo "=== shutdown ==="
kill -9 $SVR 2>/dev/null
sleep 0.3
echo "done"
