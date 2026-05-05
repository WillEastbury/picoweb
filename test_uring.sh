#!/usr/bin/env bash
# Smoke test for the io_uring backend (./picoweb --io_uring).
set -uo pipefail
cd "$(dirname "$0")"
for p in $(pgrep -x picoweb 2>/dev/null); do
    kill -9 "$p" 2>/dev/null || true
done
sleep 1

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

nohup ./picoweb --io_uring 8080 wwwroot 2 100 0 > /tmp/picoweb_uring.log 2>&1 < /dev/null &
pid=$!
sleep 1.5

if ! kill -0 $pid 2>/dev/null; then
    echo "FATAL: picoweb --io_uring exited before smoke test could start"
    cat /tmp/picoweb_uring.log
    exit 1
fi
echo "io_uring backend started, pid=$pid"
grep 'backend=io_uring' /tmp/picoweb_uring.log || fail "no 'backend=io_uring' in startup banner"

# === TEST 1: simple GET / ===
echo "=== TEST 1: GET / via io_uring ==="
out=$(curl -sS --max-time 5 -i -H 'Host: localhost' http://127.0.0.1:8080/ 2>&1)
echo "$out" | head -5
echo "$out" | head -1 | grep -q '200 OK' && ok "200 OK" || fail "no 200"
echo "$out" | grep -qi 'Server: picoweb' && ok "picoweb server header" || fail "missing server header"

# === TEST 2: chromed page ===
echo "=== TEST 2: chromed HTML wraps body ==="
out=$(curl -sS --max-time 5 -H 'Host: localhost' http://127.0.0.1:8080/)
echo "$out" | grep -q 'CHROME-HEADER' && ok "chrome-header present" || fail "no chrome-header"
echo "$out" | grep -q 'CHROME-FOOTER' && ok "chrome-footer present" || fail "no chrome-footer"

# === TEST 3: HEAD ===
echo "=== TEST 3: HEAD / suppresses body ==="
out=$(curl -sS --max-time 5 --max-time 5 -I -H 'Host: localhost' http://127.0.0.1:8080/)
sz=$(echo "$out" | tr -d '\r' | awk '/^Content-Length:/ {print $2; exit}')
[[ -n "$sz" && "$sz" -gt 0 ]] && ok "HEAD advertises Content-Length=$sz" || fail "HEAD missing CL"

# === TEST 4: /health ===
echo "=== TEST 4: /health returns OK ==="
out=$(curl -sS --max-time 5 -H 'Host: localhost' http://127.0.0.1:8080/health)
[[ "$out" == "OK" ]] && ok "/health = OK" || fail "/health body wrong: '$out'"

# === TEST 5: keep-alive (50 sequential requests, single TCP connection) ===
echo "=== TEST 5: keep-alive serves 50 sequential requests ==="
ok_count=0
for i in $(seq 1 50); do
    code=$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' \
                -H 'Host: localhost' http://127.0.0.1:8080/)
    [[ "$code" == "200" ]] && ok_count=$((ok_count+1))
done
[[ "$ok_count" == "50" ]] && ok "50/50 sequential 200s" || fail "got $ok_count/50"

# === TEST 6: picoweb-compress through io_uring ===
echo "=== TEST 6: Accept-Encoding: picoweb-compress via io_uring ==="
out=$(curl -sS --max-time 5 -i -H 'Host: localhost' -H 'Accept-Encoding: picoweb-compress' http://127.0.0.1:8080/)
echo "$out" | head -8
echo "$out" | grep -qi 'Content-Encoding: picoweb-compress' \
    && ok "compressed variant served via io_uring" \
    || fail "io_uring backend missed the compressed variant swap"

# === TEST 7: 404 ===
echo "=== TEST 7: missing path -> 404 ==="
code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -H 'Host: localhost' http://127.0.0.1:8080/does-not-exist)
[[ "$code" == "404" ]] && ok "404" || fail "expected 404 got $code"

# === Cleanup ===
kill -INT $pid 2>/dev/null
sleep 0.5
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done

echo
echo "=== Server log tail ==="
tail -10 /tmp/picoweb_uring.log
echo "=== RESULTS: PASS=$PASS  FAIL=$FAIL ==="
exit $FAIL
