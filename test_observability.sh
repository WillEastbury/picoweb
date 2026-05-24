#!/usr/bin/env bash
set -euo pipefail

PORT=${PORT:-18095}
WWW=${WWW:-/tmp/picoweb-observe-www}
VOL=${VOL:-/tmp/picoweb-observe.wal}
LOG=${LOG:-/tmp/picoweb-observe.log}
BODY=${BODY:-/tmp/picoweb-observe-body}
TOKEN_FILE=${TOKEN_FILE:-/tmp/picoweb-observe-token}

cleanup() {
    kill "$(cat /tmp/picoweb-observe-test.pid 2>/dev/null)" 2>/dev/null || true
    rm -f /tmp/picoweb-observe-test.pid "$BODY" "$TOKEN_FILE"
}
trap cleanup EXIT

rm -rf "$WWW"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"
rm -f "$VOL" "$LOG"

PICOWEB_ACCESS_LOG=1 ./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$PORT" "$WWW" 1 100 0 64 > "$LOG" 2>&1 &
PID=$!
echo "$PID" > /tmp/picoweb-observe-test.pid
sleep 0.3

curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" "http://127.0.0.1:$PORT/healthz"
grep -q '"status":"live"' "$BODY"

curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" "http://127.0.0.1:$PORT/readyz"
grep -q '"writes":"enabled"' "$BODY"

code=$(curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" -w '%{http_code}' "http://127.0.0.1:$PORT/no-such-page")
test "$code" = 404

code=$(curl -sS --max-time 3 -o "$TOKEN_FILE" -w '%{http_code}' \
    -H 'Host: localhost' \
    -X POST "http://127.0.0.1:$PORT/api/scores/start")
test "$code" = 200
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$TOKEN_FILE")
test -n "$TOKEN"

code=$(curl -sS --max-time 3 -o "$BODY" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H 'Host: localhost' \
    -H "X-Score-Token: $TOKEN" \
    -d '{"name":"Observe","score":777}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 201

code=$(curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" -w '%{http_code}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 200
grep -q '"name":"Observe"' "$BODY"

code=$(curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" -w '%{http_code}' \
    "http://127.0.0.1:$PORT/metricsz")
test "$code" = 200
grep -Eq 'picoweb_requests_total\{route="healthz"\} [1-9][0-9]*' "$BODY"
grep -Eq 'picoweb_requests_total\{route="readyz"\} [1-9][0-9]*' "$BODY"
grep -Eq 'picoweb_requests_total\{route="scores"\} [1-9][0-9]*' "$BODY"
grep -Eq 'picoweb_request_status_total\{route="static",class="4xx"\} [1-9][0-9]*' "$BODY"
grep -Eq 'picowal_operations_total\{op="write"\} [1-9][0-9]*' "$BODY"
grep -Eq 'picowal_operations_total\{op="read"\} [1-9][0-9]*' "$BODY"
grep -Eq 'picowal_storage_latency_us_sum\{op="write"\} [0-9]+' "$BODY"
grep -Eq 'picowal_lock_wait_us_sum\{op="write"\} [0-9]+' "$BODY"

grep -q '"event":"access"' "$LOG"
grep -q '"route":"scores"' "$LOG"
grep -q '"status":201' "$LOG"

echo "observability ok"
