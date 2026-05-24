#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-18096}
WWW=${WWW:-/tmp/picoweb-integrity-www}
VOL=${VOL:-/tmp/picoweb-integrity.wal}
BODY=${BODY:-/tmp/picoweb-integrity-body}
LOG=${LOG:-/tmp/picoweb-integrity.log}
PIDFILE=${PIDFILE:-/tmp/picoweb-integrity.pid}

cleanup() {
    kill "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null || true
    rm -f "$PIDFILE" "$BODY"
}
trap cleanup EXIT

rm -rf "$WWW"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"
rm -f "$VOL" "$LOG"

start_server() {
    ./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
        --picowal-public-http "$@" "$PORT" "$WWW" 1 100 0 64 > "$LOG" 2>&1 &
    PID=$!
    echo "$PID" > "$PIDFILE"
    sleep 0.4
}

stop_server() {
    kill "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null || true
    wait "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null || true
    rm -f "$PIDFILE"
}

put_record() {
    local rec="$1"
    local body="$2"
    local code
    code=$(curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" -w '%{http_code}' \
        -X PUT --data "$body" "http://127.0.0.1:$PORT/wal/12/$rec") || code=000
    test "$code" = 204
}

start_server --picowal-format
put_record 1 '{"v":1}'
put_record 2 '{"v":2}'
stop_server

# Record slots are sector-aligned: superblock at 0, records at 512, 1024, ...
# Flip one payload byte in the last record to simulate a torn/crashed tail write.
printf X | dd of="$VOL" bs=1 seek=$((1024 + 32)) conv=notrunc status=none

start_server
curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" "http://127.0.0.1:$PORT/readyz"
grep -q '"status":"tail_truncated"' "$BODY"
grep -q '"records_recovered":1' "$BODY"
grep -q '"corrupt_records":1' "$BODY"

code=$(curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" -w '%{http_code}' \
    "http://127.0.0.1:$PORT/wal/12/1") || code=000
test "$code" = 200
code=$(curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" -w '%{http_code}' \
    "http://127.0.0.1:$PORT/wal/12/2") || code=000
test "$code" = 404
curl -sS --max-time 3 -H 'Host: localhost' -o "$BODY" "http://127.0.0.1:$PORT/metricsz"
grep -q '^picowal_recovery_status 3$' "$BODY"
grep -q '^picowal_recovery_corrupt_records 1$' "$BODY"
stop_server

rm -f "$VOL"
start_server --picowal-format
put_record 1 '{"v":1}'
put_record 2 '{"v":2}'
put_record 3 '{"v":3}'
stop_server

# Corruption in the middle with a valid later record is ambiguous data loss.
# Startup must fail rather than overwrite plausible records after the gap.
printf X | dd of="$VOL" bs=1 seek=$((1024 + 32)) conv=notrunc status=none
set +e
./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    --picowal-public-http "$PORT" "$WWW" 1 100 0 64 > "$LOG" 2>&1
rc=$?
set -e
test "$rc" != 0
grep -q 'recovery failed status=corrupt' "$LOG"

printf 'picowal integrity ok\n'
