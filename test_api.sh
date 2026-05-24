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
SCRATCH="${PICOWEB_TEST_DIR:-.test-api-run}"
ROOT="$SCRATCH/api-data"
WWW="$SCRATCH/wwwroot"
LOG="$SCRATCH/picoweb-api-test.log"
PIDFILE="$SCRATCH/picoweb-api-test.pid"
BODY="$SCRATCH/api-test-body"
kill "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null || true
rm -rf "$SCRATCH"
mkdir -p "$ROOT" "$WWW"
mkdir -p "$WWW/localhost"
echo '<h1>hi</h1>' > "$WWW/localhost/index.html"

sleep 0.2

./picoweb --api-root="$ROOT" "$PORT" "$WWW" 1 100 0 64 > "$LOG" 2>&1 &
PID=$!
echo "$PID" > "$PIDFILE"
trap 'kill "$PID" 2>/dev/null; rm -rf "$SCRATCH"' EXIT
sleep 0.4

fail=0

assert_code() {
    local expected="$1"; shift
    local label="$1"; shift
    local got
    got=$(curl -sS --max-time 3 -o "$BODY" -w '%{http_code}' "$@") || got=000
    if [ "$got" = "$expected" ]; then
        echo "ok   $label -> $got"
    else
        echo "FAIL $label -> $got (expected $expected)"
        echo "     body: $(head -c 200 "$BODY")"
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

# Minimal request-context plumbing headers (upstream SSO principal + tenant app/env).
ctx_hdr="$SCRATCH/ctx.headers"
ctx_code=$(curl -sS --max-time 3 -o "$BODY" -D "$ctx_hdr" -w '%{http_code}' \
    -H 'Host: contoso.dev.local' \
    -H 'X-PW-Tenant: contoso.orders.dev' \
    -H 'X-Auth-Request-User: alice@example.com' \
    "http://127.0.0.1:$PORT/api/things/t1") || ctx_code=000
if [ "$ctx_code" = "200" ] && \
   grep -qi '^X-PW-Principal-Id: alice@example.com' "$ctx_hdr" && \
   grep -qi '^X-PW-Tenant-Id: contoso' "$ctx_hdr" && \
   grep -qi '^X-PW-Tenant-System: dev' "$ctx_hdr"; then
    echo "ok   request context headers"
else
    echo "FAIL request context headers -> $ctx_code"
    sed -n '1,30p' "$ctx_hdr"
    fail=$((fail + 1))
fi
rm -f "$ctx_hdr"

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

# Symlink-hardening checks (must not follow symlinked object files/dirs).
ln -s /etc/passwd "$ROOT/things/escape.json"
assert_code 500 "GET symlinked object blocked" "http://127.0.0.1:$PORT/api/things/escape"
rm -f "$ROOT/things/escape.json"
ln -s "$SCRATCH" "$ROOT/evilcoll"
assert_code 500 "PUT symlinked collection blocked" -X PUT --data '{}' \
            "http://127.0.0.1:$PORT/api/evilcoll/x"
rm -f "$ROOT/evilcoll"

# Body size cap (API_REQ_BODY_CAP = 6144). The 413 short-circuits without
# the server having to buffer the body, so use Content-Length only.
big_body="$SCRATCH/big-body.bin"
head -c 7000 /dev/zero > "$big_body"
assert_code 413 "PUT  oversize CL"       -X PUT \
            -H 'Transfer-Encoding:' \
            -H 'Expect:' \
            --data-binary @"$big_body" \
            "http://127.0.0.1:$PORT/api/things/big"

# Static path still works alongside API
assert_code 200 "static / still served"  -H 'Host: localhost' "http://127.0.0.1:$PORT/"

sec_hdr="$SCRATCH/security.headers"
sec_code=$(curl -sS --max-time 3 -o "$BODY" -D "$sec_hdr" \
    -w '%{http_code}' -H 'Host: localhost' "http://127.0.0.1:$PORT/") || sec_code=000
if [ "$sec_code" = "200" ] && \
   grep -qi '^Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "$sec_hdr" && \
   grep -qi "^Content-Security-Policy: .*default-src 'self'" "$sec_hdr" && \
   grep -qi '^Referrer-Policy: strict-origin-when-cross-origin' "$sec_hdr" && \
   grep -qi '^Permissions-Policy: .*camera=()' "$sec_hdr"; then
    echo "ok   static security headers"
else
    echo "FAIL static security headers -> $sec_code"
    sed -n '1,30p' "$sec_hdr"
    fail=$((fail + 1))
fi
rm -f "$sec_hdr"

api_sec_hdr="$SCRATCH/api-security.headers"
api_sec_code=$(curl -sS --max-time 3 -o "$BODY" -D "$api_sec_hdr" \
    -w '%{http_code}' "http://127.0.0.1:$PORT/api/things/t2") || api_sec_code=000
if [ "$api_sec_code" = "200" ] && \
   grep -qi '^Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "$api_sec_hdr" && \
   grep -qi "^Content-Security-Policy: .*connect-src 'self'" "$api_sec_hdr" && \
   grep -qi '^Referrer-Policy: strict-origin-when-cross-origin' "$api_sec_hdr" && \
   grep -qi '^Permissions-Policy: .*camera=()' "$api_sec_hdr"; then
    echo "ok   api security headers"
else
    echo "FAIL api security headers -> $api_sec_code"
    sed -n '1,30p' "$api_sec_hdr"
    fail=$((fail + 1))
fi
rm -f "$api_sec_hdr"

# CORS preflight / allow-origin on API path
cors_hdr="$SCRATCH/cors.headers"
cors_code=$(curl -sS --max-time 3 -o "$BODY" -D "$cors_hdr" -w '%{http_code}' \
    -X OPTIONS \
    -H 'Origin: https://app.example' \
    -H 'Access-Control-Request-Method: PUT' \
    -H 'Access-Control-Request-Headers: Content-Type, X-PW-Auth' \
    "http://127.0.0.1:$PORT/api/things/t2") || cors_code=000
if [ "$cors_code" = "204" ] && \
   grep -qi '^Access-Control-Allow-Origin: https://app.example' "$cors_hdr" && \
   grep -qi '^Access-Control-Allow-Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS' "$cors_hdr"; then
    echo "ok   OPTIONS preflight cors -> $cors_code"
else
    echo "FAIL OPTIONS preflight cors -> $cors_code (expected 204 + CORS headers)"
    echo "     headers:"
    sed -n '1,30p' "$cors_hdr"
    fail=$((fail + 1))
fi
rm -f "$cors_hdr"

echo
if [ $fail -eq 0 ]; then
    echo "PASS — all api tests green"
    exit 0
else
    echo "FAIL — $fail test(s) failed"
    echo "--- server log tail ---"
    tail -30 "$LOG"
    exit 1
fi
