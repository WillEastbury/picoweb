#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PORT1="${PORT1:-18111}"
PORT2="${PORT2:-18112}"
VOL="$(mktemp /tmp/picowal-single-writer.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"

PID1=""
PID2=""
cleanup() {
    if [ -n "$PID1" ]; then kill "$PID1" 2>/dev/null || true; fi
    if [ -n "$PID2" ]; then kill "$PID2" 2>/dev/null || true; fi
    rm -f "$VOL"
    rm -rf "$WWW"
}
trap cleanup EXIT

./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 --picowal-format \
    "$PORT1" "$WWW" 1 100 0 64 > /tmp/picowal-single-writer-1.log 2>&1 &
PID1=$!
sleep 0.4

curl -sS --max-time 3 -o /tmp/picowal-single-writer-body -w '%{http_code}' \
    "http://127.0.0.1:$PORT1/readyz" | grep -q '^200$'

set +e
./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$PORT2" "$WWW" 1 100 0 64 > /tmp/picowal-single-writer-2.log 2>&1 &
PID2=$!
sleep 0.5
stat="$(ps -o stat= -p "$PID2" 2>/dev/null | tr -d ' ')"
set -e

if [ -n "$stat" ] && [ "${stat#Z}" = "$stat" ]; then
    echo "second picowal writer unexpectedly started"
    exit 1
fi
wait "$PID2" 2>/dev/null || true
PID2=""

echo "picowal single-writer lock ok"
