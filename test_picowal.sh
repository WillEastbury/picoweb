#!/usr/bin/env bash
# test_picowal.sh — exercise picowal raw-volume API backend.

set -u
cd "$(dirname "$0")"

PORT="${1:-8776}"
VOL="$(mktemp /tmp/picowal.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"
echo '<h1>hi</h1>' > "$WWW/localhost/index.html"

kill "$(cat /tmp/picoweb-picowal-test.pid 2>/dev/null)" 2>/dev/null || true
sleep 0.2

start_server() {
    ./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 --picowal-public-http "$@" \
        "$PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-picowal-test.log 2>&1 &
    PID=$!
    echo "$PID" > /tmp/picoweb-picowal-test.pid
    sleep 0.4
}

stop_server() {
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
}

start_server --picowal-format
trap 'stop_server; rm -f "$VOL"; rm -rf "$WWW"' EXIT

fail=0

assert_code() {
    local expected="$1"; shift
    local label="$1"; shift
    local got
    got=$(curl -sS --max-time 3 -o /tmp/picowal-test-body -w '%{http_code}' "$@") || got=000
    if [ "$got" = "$expected" ]; then
        echo "ok   $label -> $got"
    else
        echo "FAIL $label -> $got (expected $expected)"
        echo "     body: $(head -c 200 /tmp/picowal-test-body 2>/dev/null)"
        fail=$((fail + 1))
    fi
}

assert_code 204 "PUT  wal record" -X PUT --data '{"v":1}' \
            "http://127.0.0.1:$PORT/wal/12/345"
assert_code 200 "GET  wal record" "http://127.0.0.1:$PORT/wal/12/345"
assert_code 200 "HEAD wal record" -I "http://127.0.0.1:$PORT/wal/12/345"

ctx_hdr="$(mktemp)"
ctx_code=$(curl -sS --max-time 3 -o /tmp/picowal-test-body -D "$ctx_hdr" -w '%{http_code}' \
    -H 'Host: fabrikam.qa.local' \
    -H 'X-PW-Tenant: fabrikam.catalog.qa' \
    "http://127.0.0.1:$PORT/wal/12/345") || ctx_code=000
if [ "$ctx_code" = "200" ] && \
   grep -qi '^X-PW-Principal-Id: anonymous' "$ctx_hdr" && \
   grep -qi '^X-PW-Tenant-Id: fabrikam' "$ctx_hdr" && \
   grep -qi '^X-PW-Tenant-System: qa' "$ctx_hdr"; then
    echo "ok   wal request context headers"
else
    echo "FAIL wal request context headers -> $ctx_code"
    sed -n '1,30p' "$ctx_hdr"
    fail=$((fail + 1))
fi
rm -f "$ctx_hdr"

got_body=$(curl -sS --max-time 3 "http://127.0.0.1:$PORT/wal/12/345")
if [ "$got_body" = '{"v":1}' ]; then
    echo "ok   GET body roundtrip"
else
    echo "FAIL GET body got '$got_body' expected '{\"v\":1}'"
    fail=$((fail + 1))
fi

assert_code 201 "POST explicit create" -X POST --data '{"v":2}' \
            "http://127.0.0.1:$PORT/wal/12/999"
assert_code 409 "POST explicit conflict" -X POST --data '{"v":3}' \
            "http://127.0.0.1:$PORT/wal/12/999"
assert_code 201 "POST auto record" -X POST --data '{"auto":true}' \
            "http://127.0.0.1:$PORT/wal/12"

# Query + join flow (primary pack 12 joins pack 13 via field "13_id")
assert_code 204 "PUT  join pack rec1" -X PUT --data '{"city":"London","country":"UK"}' \
            "http://127.0.0.1:$PORT/wal/13/1"
assert_code 204 "PUT  join pack rec2" -X PUT --data '{"city":"Paris","country":"FR"}' \
            "http://127.0.0.1:$PORT/wal/13/2"
assert_code 204 "PUT  primary recA" -X PUT --data '{"name":"Ann","13_id":1}' \
            "http://127.0.0.1:$PORT/wal/12/101"
assert_code 204 "PUT  primary recB" -X PUT --data '{"name":"Bob","13_id":2}' \
            "http://127.0.0.1:$PORT/wal/12/102"

# Pack-name registry (pack 1) and schema store (pack 2)
assert_code 204 "PUT  metadata name orders" -X PUT --data '{"name":"orders","pack":12}' \
            "http://127.0.0.1:$PORT/wal/metadata/name/12"
assert_code 204 "PUT  metadata name countries" -X PUT --data '{"name":"countries","pack":13}' \
            "http://127.0.0.1:$PORT/wal/metadata/name/13"
assert_code 204 "PUT  metadata schema orders" -X PUT --data '{"fields":"name,13_id,status,email","required":"name,13_id,status","joins":"13=13_id","types":"name=string;13_id=number;status=string;email=string?","email":"email","regex":"status=^(Placed|Shipped|Delivered)$","transitions":"status=Placed>Shipped|Shipped>Delivered"}' \
            "http://127.0.0.1:$PORT/wal/metadata/schema/12"
assert_code 204 "PUT  metadata schema countries" -X PUT --data '{"fields":"city,country"}' \
            "http://127.0.0.1:$PORT/wal/metadata/schema/13"
assert_code 200 "GET  schema orders" "http://127.0.0.1:$PORT/wal/schema/12"
assert_code 200 "GET  metadata wrapper" "http://127.0.0.1:$PORT/wal/metadata/12"
meta_out=$(cat /tmp/picowal-test-body)
if echo "$meta_out" | grep -q '"pack":12' && \
   echo "$meta_out" | grep -q '"pack1":' && \
   echo "$meta_out" | grep -q '"pack2":'; then
    echo "ok   metadata wrapper output"
else
    echo "FAIL metadata wrapper output: $meta_out"
    fail=$((fail + 1))
fi

assert_code 200 "GET  form orders" "http://127.0.0.1:$PORT/wal/forms/12"
form_out=$(cat /tmp/picowal-test-body)
if echo "$form_out" | grep -q '"pack":12' && \
   echo "$form_out" | grep -q '"entity":"orders"' && \
   echo "$form_out" | grep -q '"name":"name"' && \
   echo "$form_out" | grep -q '"name":"13_id"' && \
   echo "$form_out" | grep -q '"relation_pack":13'; then
    echo "ok   metadata form output"
else
    echo "FAIL metadata form output: $form_out"
    fail=$((fail + 1))
fi

assert_code 404 "GET  form missing schema" "http://127.0.0.1:$PORT/wal/forms/77"

assert_code 204 "validation good write" -X PUT --data '{"name":"Cara","13_id":1,"status":"Placed","email":"cara@example.com"}' \
            "http://127.0.0.1:$PORT/wal/12/150"
assert_code 409 "validation lookup missing" -X PUT --data '{"name":"Dana","13_id":999,"status":"Placed"}' \
            "http://127.0.0.1:$PORT/wal/12/151"
assert_code 400 "validation required missing" -X PUT --data '{"name":"Eli","13_id":1}' \
            "http://127.0.0.1:$PORT/wal/12/152"
assert_code 400 "validation regex fail" -X PUT --data '{"name":"Finn","13_id":1,"status":"Unknown"}' \
            "http://127.0.0.1:$PORT/wal/12/153"
assert_code 400 "validation email fail" -X PUT --data '{"name":"Gia","13_id":1,"status":"Placed","email":"bad-email"}' \
            "http://127.0.0.1:$PORT/wal/12/154"
assert_code 409 "validation transition blocked" -X PUT --data '{"name":"Cara","13_id":1,"status":"Delivered","email":"cara@example.com"}' \
            "http://127.0.0.1:$PORT/wal/12/150"
assert_code 204 "validation transition allowed" -X PUT --data '{"name":"Cara","13_id":1,"status":"Shipped","email":"cara@example.com"}' \
            "http://127.0.0.1:$PORT/wal/12/150"
assert_code 409 "validation delete ref blocked" -X DELETE \
            "http://127.0.0.1:$PORT/wal/13/1"

query_body=$'S:name,countries.city\nF:orders,countries\nW:countries.country|==|UK'
assert_code 200 "POST query join named packs" -X POST --data-binary "$query_body" \
            "http://127.0.0.1:$PORT/wal/query"
query_out=$(cat /tmp/picowal-test-body)
if echo "$query_out" | grep -q '"name":"Ann"' && \
   echo "$query_out" | grep -q '"countries.city":"London"' && \
   ! echo "$query_out" | grep -q '"name":"Bob"'; then
    echo "ok   query join output (named packs + schema)"
else
    echo "FAIL query join output: $query_out"
    fail=$((fail + 1))
fi

assert_code 200 "POST report endpoint" -X POST --data-binary "$query_body" \
            "http://127.0.0.1:$PORT/wal/report"
report_out=$(cat /tmp/picowal-test-body)
if echo "$report_out" | grep -q '"kind":"report"' && \
   echo "$report_out" | grep -q '"report":' && \
   echo "$report_out" | grep -q '"count":'; then
    echo "ok   report output"
else
    echo "FAIL report output: $report_out"
    fail=$((fail + 1))
fi

dashboard_body=$'T:Open Orders\nS:name\nF:orders\n---\nT:Broken Panel\nS:name\nF:missingpack'
assert_code 200 "POST dashboard endpoint" -X POST --data-binary "$dashboard_body" \
            "http://127.0.0.1:$PORT/wal/dashboard"
dash_out=$(cat /tmp/picowal-test-body)
if echo "$dash_out" | grep -q '"kind":"dashboard"' && \
   echo "$dash_out" | grep -q '"panels":' && \
   echo "$dash_out" | grep -q '"error":'; then
    echo "ok   dashboard output"
else
    echo "FAIL dashboard output: $dash_out"
    fail=$((fail + 1))
fi

assert_code 400 "invalid card id" -X PUT --data '{}' \
            "http://127.0.0.1:$PORT/wal/deck/1"
assert_code 400 "invalid record id" -X PUT --data '{}' \
            "http://127.0.0.1:$PORT/wal/1/notnum"

assert_code 204 "DELETE existing" -X DELETE "http://127.0.0.1:$PORT/wal/12/345"
assert_code 404 "GET deleted" "http://127.0.0.1:$PORT/wal/12/345"

# Persistence check: restart without format and ensure previous key survives.
stop_server
start_server
assert_code 200 "GET persists after restart" "http://127.0.0.1:$PORT/wal/12/999"

# Auth gate check: when OIDC cookie auth is enabled, /wal routes require
# both X-PW-Auth header and a valid short-lived session cookie.
stop_server
start_server --oidc-cookie-auth --oidc-google-client-id=test-google --oidc-entra-client-id=test-entra
assert_code 403 "auth gate missing header" "http://127.0.0.1:$PORT/wal/12/999"
assert_code 401 "auth gate missing cookie" -H 'X-PW-Auth: 1' \
            "http://127.0.0.1:$PORT/wal/12/999"
assert_code 403 "auth login missing header" -X POST --data '{"provider":"google","access_token":"x"}' \
            "http://127.0.0.1:$PORT/wal/auth/login"
assert_code 204 "auth logout no cookie" -X POST -H 'X-PW-Auth: 1' \
            "http://127.0.0.1:$PORT/wal/auth/logout"

cors_hdr="$(mktemp)"
cors_code=$(curl -sS --max-time 3 -o /tmp/picowal-test-body -D "$cors_hdr" -w '%{http_code}' \
    -X OPTIONS \
    -H 'Origin: https://app.example' \
    -H 'Access-Control-Request-Method: GET' \
    -H 'Access-Control-Request-Headers: X-PW-Auth' \
    "http://127.0.0.1:$PORT/wal/12/999") || cors_code=000
if [ "$cors_code" = "204" ] && \
   grep -qi '^Access-Control-Allow-Origin: https://app.example' "$cors_hdr"; then
    echo "ok   wal cors preflight -> $cors_code"
else
    echo "FAIL wal cors preflight -> $cors_code (expected 204 + CORS headers)"
    sed -n '1,30p' "$cors_hdr"
    fail=$((fail + 1))
fi
rm -f "$cors_hdr"

echo
if [ $fail -eq 0 ]; then
    echo "PASS — all picowal tests green"
    exit 0
else
    echo "FAIL — $fail test(s) failed"
    echo "--- server log tail ---"
    tail -30 /tmp/picoweb-picowal-test.log
    exit 1
fi
