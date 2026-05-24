#!/usr/bin/env bash
set -euo pipefail

PORT=${PORT:-18097}
RESTORE_PORT=${RESTORE_PORT:-18098}
WWW=${WWW:-/tmp/picoweb-shutdown-www}
VOL=${VOL:-/tmp/picoweb-shutdown.wal}

cleanup() {
    kill "$(cat /tmp/picoweb-shutdown-test.pid 2>/dev/null)" 2>/dev/null || true
    kill "$(cat /tmp/picoweb-shutdown-restore-test.pid 2>/dev/null)" 2>/dev/null || true
    rm -f /tmp/picoweb-shutdown-test.pid /tmp/picoweb-shutdown-restore-test.pid
    rm -f /tmp/picoweb-shutdown-body /tmp/picoweb-shutdown-token
}
trap cleanup EXIT

rm -rf "$WWW"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"
rm -f "$VOL"

PICOWEB_SHUTDOWN_LAMEDUCK_MS=1000 PICOWEB_SHUTDOWN_DRAIN_MS=2500 \
    ./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-shutdown-test.log 2>&1 &
PID=$!
echo "$PID" > /tmp/picoweb-shutdown-test.pid
sleep 0.3

issue_token() {
    curl -sS --max-time 3 -o /tmp/picoweb-shutdown-token -w '%{http_code}' \
        -X POST "http://127.0.0.1:$PORT/api/scores/start"
}

token_from_file() {
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p' /tmp/picoweb-shutdown-token
}

code=$(issue_token)
test "$code" = 200
TOKEN=$(token_from_file)
test -n "$TOKEN"

code=$(curl -sS --max-time 3 -o /tmp/picoweb-shutdown-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $TOKEN" \
    -d '{"name":"BeforeTerm","score":444}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 201

kill -TERM "$PID"

for _ in $(seq 1 20); do
    code=$(curl -sS --max-time 3 -o /tmp/picoweb-shutdown-body -w '%{http_code}' \
        "http://127.0.0.1:$PORT/readyz") || code=000
    if [ "$code" = 503 ] && grep -q '"writes":"draining"' /tmp/picoweb-shutdown-body; then
        break
    fi
    sleep 0.05
done
test "$code" = 503
grep -q '"writes":"draining"' /tmp/picoweb-shutdown-body

code=$(issue_token) || code=000
test "$code" = 503

for _ in $(seq 1 40); do
    if ! kill -0 "$PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if kill -0 "$PID" 2>/dev/null; then
    echo "picoweb did not exit during graceful shutdown"
    exit 1
fi

./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$RESTORE_PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-shutdown-restore-test.log 2>&1 &
RESTORE_PID=$!
echo "$RESTORE_PID" > /tmp/picoweb-shutdown-restore-test.pid
sleep 0.3

code=$(curl -sS --max-time 3 -o /tmp/picoweb-shutdown-body -w '%{http_code}' \
    "http://127.0.0.1:$RESTORE_PORT/api/scores")
test "$code" = 200
grep -q '"name":"BeforeTerm"' /tmp/picoweb-shutdown-body

echo "graceful shutdown ok"
