#!/usr/bin/env bash
# test_api.sh — exercise the JSON-file CRUD API end-to-end.
# Usage: ./test_api.sh [PORT]
#
# Spins up picoweb in epoll mode with --api-root pointing at a temp dir,
# runs PUT/GET/HEAD/POST/DELETE flows, and asserts status codes + bodies.
# Exits non-zero on any failure.

set -u
cd "$(dirname "$0")"

PORT="${1:-8765}"
ROOT="$(mktemp -d)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"
echo '<h1>hi</h1>' > "$WWW/localhost/index.html"

kill "$(cat /tmp/picoweb-api-test.pid 2>/dev/null)" 2>/dev/null || true
sleep 0.2

./picoweb --api-root="$ROOT" "$PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-api-test.log 2>&1 &
PID=$!
echo "$PID" > /tmp/picoweb-api-test.pid
trap 'kill "$PID" 2>/dev/null; rm -rf "$ROOT" "$WWW"' EXIT
sleep 0.4

fail=0

assert_code() {
    local expected="$1"; shift
    local label="$1"; shift
    local got
    got=$(curl -sS --max-time 3 -o /tmp/api-test-body -w '%{http_code}' "$@") || got=000
    if [ "$got" = "$expected" ]; then
        echo "ok   $label -> $got"
    else
        echo "FAIL $label -> $got (expected $expected)"
        echo "     body: $(head -c 200 /tmp/api-test-body)"
        fail=$((fail + 1))
    fi
}

# Round-trip
assert_code 204 "PUT  new record"        -X PUT  -H 'Content-Type: application/json' \
            --data '{"a":1}' "http://127.0.0.1:$PORT/api/things/t1"
assert_code 200 "GET  existing"          "http://127.0.0.1:$PORT/api/things/t1"
assert_code 200 "HEAD existing"          -I "http://127.0.0.1:$PORT/api/things/t1"
assert_code 204 "PUT  replace"           -X PUT --data '{"a":2}' \
            "http://127.0.0.1:$PORT/api/things/t1"

# Body content survives a round-trip
got_body=$(curl -sS --max-time 3 "http://127.0.0.1:$PORT/api/things/t1")
if [ "$got_body" = '{"a":2}' ]; then
    echo "ok   GET body matches replacement"
else
    echo "FAIL GET body got '$got_body' expected '{\"a\":2}'"
    fail=$((fail + 1))
fi

# POST semantics
assert_code 409 "POST conflict"          -X POST --data '{"x":1}' \
            "http://127.0.0.1:$PORT/api/things/t1"
assert_code 201 "POST autogen"           -X POST --data '{"new":true}' \
            "http://127.0.0.1:$PORT/api/things"
assert_code 201 "POST explicit-new"      -X POST --data '{}' \
            "http://127.0.0.1:$PORT/api/things/t2"

# DELETE
assert_code 204 "DELETE existing"        -X DELETE "http://127.0.0.1:$PORT/api/things/t1"
assert_code 404 "GET    after DELETE"    "http://127.0.0.1:$PORT/api/things/t1"
assert_code 404 "DELETE missing"         -X DELETE "http://127.0.0.1:$PORT/api/things/t1"

# Validation
assert_code 400 "POST missing id but body needed" -X DELETE "http://127.0.0.1:$PORT/api/things/"
assert_code 400 "id with dot"            "http://127.0.0.1:$PORT/api/things/.hidden"
assert_code 400 "id traversal collapsed"  --path-as-is "http://127.0.0.1:$PORT/api/things/../etc"
assert_code 400 "non-ascii id"           "http://127.0.0.1:$PORT/api/things/h%C3%A9"

# Body size cap (API_REQ_BODY_CAP = 6144). The 413 short-circuits without
# the server having to buffer the body, so use Content-Length only.
assert_code 413 "PUT  oversize CL"       -X PUT \
            -H 'Transfer-Encoding:' \
            -H 'Expect:' \
            --data-binary @<(head -c 7000 /dev/zero) \
            "http://127.0.0.1:$PORT/api/things/big"

# Static path still works alongside API
assert_code 200 "static / still served"  -H 'Host: localhost' "http://127.0.0.1:$PORT/"

# Unknown method on API path
assert_code 405 "OPTIONS not allowed"    -X OPTIONS "http://127.0.0.1:$PORT/api/things/t2"

echo
if [ $fail -eq 0 ]; then
    echo "PASS — all api tests green"
    exit 0
else
    echo "FAIL — $fail test(s) failed"
    echo "--- server log tail ---"
    tail -30 /tmp/picoweb-api-test.log
    exit 1
fi
