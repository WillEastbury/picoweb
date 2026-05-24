#!/usr/bin/env bash
set -euo pipefail

PORT=${PORT:-18092}
WWW=${WWW:-/tmp/picoweb-health-www}
VOL=${VOL:-/tmp/picoweb-health.wal}

cleanup() {
    kill "$(cat /tmp/picoweb-health-test.pid 2>/dev/null)" 2>/dev/null || true
    rm -f /tmp/picoweb-health-test.pid /tmp/picoweb-health-body
}
trap cleanup EXIT

rm -rf "$WWW"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"
rm -f "$VOL"

./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-health-test.log 2>&1 &
PID=$!
echo "$PID" > /tmp/picoweb-health-test.pid
sleep 0.3

code=$(curl -sS --max-time 3 -o /tmp/picoweb-health-body -w '%{http_code}' \
    "http://127.0.0.1:$PORT/healthz")
test "$code" = 200
grep -q '"status":"live"' /tmp/picoweb-health-body

code=$(curl -sS --max-time 3 -o /tmp/picoweb-health-body -w '%{http_code}' \
    "http://127.0.0.1:$PORT/readyz")
test "$code" = 200
grep -q '"status":"ready"' /tmp/picoweb-health-body
grep -q '"picowal":"ready"' /tmp/picoweb-health-body

code=$(curl -sS --max-time 3 -o /tmp/picoweb-health-body -w '%{http_code}' \
    -X POST "http://127.0.0.1:$PORT/readyz")
test "$code" = 405

echo "health api ok"
