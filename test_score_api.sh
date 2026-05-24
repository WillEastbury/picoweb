#!/usr/bin/env bash
set -euo pipefail

PORT=${PORT:-18091}
WWW=${WWW:-/tmp/picoweb-score-www}
VOL=${VOL:-/tmp/picoweb-score.wal}

cleanup() {
    kill "$(cat /tmp/picoweb-score-test.pid 2>/dev/null)" 2>/dev/null || true
    rm -f /tmp/picoweb-score-test.pid /tmp/picoweb-score-body /tmp/picoweb-score-token
}
trap cleanup EXIT

rm -rf "$WWW"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"
rm -f "$VOL"

PICOWEB_SCORE_TOKEN_KEYS_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    ./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 \
    "$PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-score-test.log 2>&1 &
PID=$!
echo "$PID" > /tmp/picoweb-score-test.pid
sleep 0.3

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    "http://127.0.0.1:$PORT/wal/42")
case "$code" in
    2*) echo "raw wal unexpectedly exposed: $code"; exit 1 ;;
esac

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d '{"name":"bad","score":1}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 401

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-token -w '%{http_code}' \
    -X POST "http://127.0.0.1:$PORT/api/scores/start")
test "$code" = 200
token=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' /tmp/picoweb-score-token)
test -n "$token"

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    -X POST -d '{}' "http://127.0.0.1:$PORT/api/scores/start")
test "$code" = 400

tampered="${token%?}0"
if [ "$tampered" = "$token" ]; then tampered="${token%?}1"; fi
code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $tampered" \
    -d '{"name":"Mallory","score":999}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 401

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $token" \
    -d '{"name":"Ada","score":12345}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 201

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $token" \
    -d '{"name":"Ada","score":12345}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 401

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    "http://127.0.0.1:$PORT/api/scores")
test "$code" = 200
grep -q '"name":"Ada"' /tmp/picoweb-score-body
grep -q '"score":12345' /tmp/picoweb-score-body

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    -X GET -d '{}' "http://127.0.0.1:$PORT/api/scores")
test "$code" = 400

code=$(curl -sS --max-time 3 -o /tmp/picoweb-score-body -w '%{http_code}' \
    -X DELETE "http://127.0.0.1:$PORT/api/scores")
test "$code" = 405

curl -sS --max-time 3 "http://127.0.0.1:$PORT/metricsz" > /tmp/picoweb-score-body
grep -q 'picoweb_score_rejects_total{reason="invalid_token"} 3' /tmp/picoweb-score-body
grep -q 'picoweb_score_rejects_total{reason="invalid_body"} 2' /tmp/picoweb-score-body
grep -q 'picoweb_score_rejects_total{reason="method"} 1' /tmp/picoweb-score-body

echo "score api ok"
