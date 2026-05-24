#!/usr/bin/env bash
set -euo pipefail

PORT=${PORT:-18093}
RESTORE_PORT=${RESTORE_PORT:-18094}
WWW=${WWW:-/tmp/picoweb-backup-www}
VOL=${VOL:-/tmp/picoweb-backup.wal}
SNAP=${SNAP:-/tmp/picoweb-backup.snapshot.wal}

cleanup() {
    kill "$(cat /tmp/picoweb-backup-test.pid 2>/dev/null)" 2>/dev/null || true
    kill "$(cat /tmp/picoweb-backup-restore-test.pid 2>/dev/null)" 2>/dev/null || true
    rm -f /tmp/picoweb-backup-test.pid /tmp/picoweb-backup-restore-test.pid
    rm -f /tmp/picoweb-backup-body /tmp/picoweb-backup-token
}
trap cleanup EXIT

rm -rf "$WWW"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"
rm -f "$VOL" "$SNAP"

./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-backup-test.log 2>&1 &
PID=$!
echo "$PID" > /tmp/picoweb-backup-test.pid
sleep 0.3

issue_token() {
    curl -sS --max-time 3 -o /tmp/picoweb-backup-token -w '%{http_code}' \
        -X POST "http://127.0.0.1:$PORT/api/scores/start"
}

token_from_file() {
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p' /tmp/picoweb-backup-token
}

code=$(issue_token)
test "$code" = 200
TOKEN=$(token_from_file)
test -n "$TOKEN"

code=$(curl -sS --max-time 3 -o /tmp/picoweb-backup-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $TOKEN" \
    -d '{"name":"BeforeSnap","score":111}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 201

kill -USR1 "$PID"
for _ in $(seq 1 30); do
    code=$(curl -sS --max-time 3 -o /tmp/picoweb-backup-body -w '%{http_code}' \
        "http://127.0.0.1:$PORT/readyz") || code=000
    if [ "$code" = 200 ] && grep -q '"writes":"quiesced"' /tmp/picoweb-backup-body; then
        break
    fi
    sleep 0.1
done
test "$code" = 200
grep -q '"writes":"quiesced"' /tmp/picoweb-backup-body

code=$(curl -sS --max-time 3 -o /tmp/picoweb-backup-body -w '%{http_code}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 200
grep -q '"name":"BeforeSnap"' /tmp/picoweb-backup-body

code=$(issue_token)
test "$code" = 200
TOKEN=$(token_from_file)
test -n "$TOKEN"
code=$(curl -sS --max-time 3 -o /tmp/picoweb-backup-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $TOKEN" \
    -d '{"name":"DuringSnap","score":222}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 503

# This file copy is a local smoke test for the quiesced WAL image. Production
# backups must use a CSI/Azure VolumeSnapshot of the PVC, not kubectl cp.
cp "$VOL" "$SNAP"

kill -USR2 "$PID"
for _ in $(seq 1 30); do
    code=$(curl -sS --max-time 3 -o /tmp/picoweb-backup-body -w '%{http_code}' \
        "http://127.0.0.1:$PORT/readyz") || code=000
    if [ "$code" = 200 ] && grep -q '"writes":"enabled"' /tmp/picoweb-backup-body; then
        break
    fi
    sleep 0.1
done
test "$code" = 200
grep -q '"writes":"enabled"' /tmp/picoweb-backup-body

code=$(issue_token)
test "$code" = 200
TOKEN=$(token_from_file)
test -n "$TOKEN"
code=$(curl -sS --max-time 3 -o /tmp/picoweb-backup-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $TOKEN" \
    -d '{"name":"AfterSnap","score":333}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 201

./picoweb --picowal-device="$SNAP" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$RESTORE_PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-backup-restore-test.log 2>&1 &
RESTORE_PID=$!
echo "$RESTORE_PID" > /tmp/picoweb-backup-restore-test.pid
sleep 0.3

code=$(curl -sS --max-time 3 -o /tmp/picoweb-backup-body -w '%{http_code}' \
    "http://127.0.0.1:$RESTORE_PORT/api/scores")
test "$code" = 200
grep -q '"name":"BeforeSnap"' /tmp/picoweb-backup-body
if grep -q '"name":"AfterSnap"' /tmp/picoweb-backup-body; then
    echo "snapshot unexpectedly contains post-resume score"
    exit 1
fi

echo "backup quiesce ok"
