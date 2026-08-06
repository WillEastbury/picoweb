#!/usr/bin/env bash
# test_picowal.sh — exercise picowal raw-volume API backend.

set -u
cd "$(dirname "$0")"

PORT="${1:-8776}"
VOL="$(mktemp -d /tmp/picowal.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"
echo '<h1>hi</h1>' > "$WWW/localhost/index.html"

kill "$(cat /tmp/picoweb-picowal-test.pid 2>/dev/null)" 2>/dev/null || true
sleep 0.2

start_server() {
    ./picoweb --picowal-device="$VOL" --picowal-prefix=/wal/ --picowal-bytes=8388608 "$@" \
        "$PORT" "$WWW" 1 100 0 64 > /tmp/picoweb-picowal-test.log 2>&1 &
    PID=$!
    echo "$PID" > /tmp/picoweb-picowal-test.pid
    sleep 0.4
}

start_server --picowal-format
trap 'kill "$PID" 2>/dev/null; rm -rf "$VOL"; rm -rf "$WWW"' EXIT

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
assert_code 204 "PUT  metadata schema orders" -X PUT --data '{"title":"Orders","fields":"name,13_id,status,email","required":"name,13_id,status","joins":"13=13_id","types":"name=string;13_id=number;status=string;email=string?","email":"email","regex":"status=^(Placed|Shipped|Delivered)$","transitions":"status=Placed>Shipped|Shipped>Delivered","pages":"list,create,edit,detail","nav":"orders,countries","list_columns":"name,status,13_id","layout":"split","actions":"create,update,delete,report,dashboard","page_size":"50","default_sort":"status,-name","field_labels":"name=Order Name;13_id=Country;status=Order Status","field_placeholders":"name=SO-1001;email=owner@example.com"}' \
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
   echo "$form_out" | grep -q '"schema":' && \
   echo "$form_out" | grep -q '"fields":"name,13_id,status,email"' && \
   echo "$form_out" | grep -q '"app":' && \
   echo "$form_out" | grep -q '"model_version":1' && \
   echo "$form_out" | grep -q '"title":"Orders"' && \
   echo "$form_out" | grep -q '"pages":"list,create,edit,detail"'; then
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

echo
echo "== rich logical-type validation (bool/uintN/intN/decimal/ascii/utf8/date/time/datetime/array_u16/blob/lookup + nullable/readonly/max_lengths) =="
assert_code 204 "PUT  metadata schema widgets (rich types)" -X PUT --data \
  '{"fields":"sku,qty,price,active,tag,notes,released,opens,updated,tags,thumb,country_id","required":"sku,qty","nullable":"notes","readonly":"sku","max_lengths":"sku=8;tags=3","joins":"13=country_id","types":"sku=ascii;qty=uint16;price=decimal;active=bool;tag=utf8;notes=string;released=date;opens=time;updated=datetime;tags=array_u16;thumb=blob;country_id=lookup"}' \
  "http://127.0.0.1:$PORT/wal/metadata/schema/20"

good_widget='{"sku":"SKU-01","qty":10,"price":19.99,"active":true,"tag":"blue","notes":"ok","released":"2024-01-31","opens":"09:30:00","updated":"2024-01-31T09:30:00","tags":[1,2,3],"thumb":"aGVsbG8=","country_id":1}'
assert_code 204 "rich types: good write" -X PUT --data "$good_widget" "http://127.0.0.1:$PORT/wal/20/200"
array_query=$(curl -sS --max-time 5 -X POST --data-binary $'S:tags\nF:20' "http://127.0.0.1:$PORT/wal/query")
if printf '%s' "$array_query" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["rows"][0]["tags"] == [1,2,3]'; then
    echo "ok   query preserves selected array fields as valid JSON"
else
    echo "FAIL query array JSON output: $array_query"
    fail=$((fail + 1))
fi
assert_code 400 "rich types: uint16 out of range" -X PUT --data \
  '{"sku":"SKU-01","qty":70000,"country_id":1}' "http://127.0.0.1:$PORT/wal/20/201"
assert_code 400 "rich types: bad date" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"released":"2024-13-40","country_id":1}' "http://127.0.0.1:$PORT/wal/20/202"
assert_code 400 "rich types: bad time" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"opens":"25:99","country_id":1}' "http://127.0.0.1:$PORT/wal/20/203"
assert_code 400 "rich types: bad datetime" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"updated":"not-a-datetime","country_id":1}' "http://127.0.0.1:$PORT/wal/20/204"
assert_code 400 "rich types: array_u16 element out of range" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"tags":[1,99999],"country_id":1}' "http://127.0.0.1:$PORT/wal/20/205"
assert_code 400 "rich types: array_u16 exceeds max_lengths" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"tags":[1,2,3,4],"country_id":1}' "http://127.0.0.1:$PORT/wal/20/206"
assert_code 400 "rich types: blob invalid base64" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"thumb":"not base64!!","country_id":1}' "http://127.0.0.1:$PORT/wal/20/207"
assert_code 204 "rich types: blob as numeric byte array" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"thumb":[1,2,255],"country_id":1}' "http://127.0.0.1:$PORT/wal/20/208"
assert_code 400 "rich types: ascii field with non-ascii byte" -X PUT --data \
  '{"sku":"SKU-\u00e9","qty":1,"country_id":1}' "http://127.0.0.1:$PORT/wal/20/209"
assert_code 400 "rich types: sku exceeds max_lengths" -X PUT --data \
  '{"sku":"WAY-TOO-LONG","qty":1,"country_id":1}' "http://127.0.0.1:$PORT/wal/20/210"
assert_code 409 "rich types: lookup target does not exist" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"country_id":999}' "http://127.0.0.1:$PORT/wal/20/211"
assert_code 204 "rich types: nullable field accepts null" -X PUT --data \
  '{"sku":"SKU-01","qty":1,"notes":null,"country_id":1}' "http://127.0.0.1:$PORT/wal/20/212"
assert_code 409 "rich types: readonly field cannot change on existing record" -X PUT --data \
  '{"sku":"SKU-999","qty":11,"price":19.99,"active":true,"tag":"blue","notes":"ok","released":"2024-01-31","opens":"09:30:00","updated":"2024-01-31T09:30:00","tags":[1,2,3],"thumb":"aGVsbG8=","country_id":1}' \
  "http://127.0.0.1:$PORT/wal/20/200"
assert_code 204 "rich types: non-readonly field can change on existing record" -X PUT --data "$good_widget" \
  "http://127.0.0.1:$PORT/wal/20/200"

assert_code 204 "PUT  generic array schema with max_lengths" -X PUT --data \
  '{"fields":"tags","types":"tags=array","max_lengths":"tags=5"}' \
  "http://127.0.0.1:$PORT/wal/schema/24"
large_array_doc=$(python3 -c 'import json; print(json.dumps({"tags": list(range(200))}, separators=(",", ":")))')
assert_code 400 "generic array cannot bypass max_lengths via oversized parser capture" -X PUT --data \
  "$large_array_doc" "http://127.0.0.1:$PORT/wal/24/1"

echo
echo "== rich schema JSON round-trip preserves new metadata keys (ordinals/lookup_labels/module/public_read/children/list_columns) =="
rich_schema_doc='{"fields":"sku,qty,country_id","required":"sku,qty","nullable":"notes","readonly":"sku","max_lengths":"sku=8","ordinals":"sku=0;qty=1;country_id=2","lookup_labels":"country_id=city","joins":"13=country_id","types":"sku=ascii;qty=uint16;country_id=lookup","module":"catalog","public_read":true,"children":"21,22","list_columns":"sku,qty"}'
assert_code 204 "PUT  rich schema with all new metadata keys" -X PUT --data "$rich_schema_doc" \
            "http://127.0.0.1:$PORT/wal/metadata/schema/23"
assert_code 200 "GET  rich schema round-trip" "http://127.0.0.1:$PORT/wal/schema/23"
roundtrip_out=$(cat /tmp/picowal-test-body)
if echo "$roundtrip_out" | grep -q '"ordinals":"sku=0;qty=1;country_id=2"' && \
   echo "$roundtrip_out" | grep -q '"lookup_labels":"country_id=city"' && \
   echo "$roundtrip_out" | grep -q '"module":"catalog"' && \
   echo "$roundtrip_out" | grep -q '"public_read":true' && \
   echo "$roundtrip_out" | grep -q '"children":"21,22"' && \
   echo "$roundtrip_out" | grep -q '"list_columns":"sku,qty"' && \
   echo "$roundtrip_out" | grep -q '"nullable":"notes"' && \
   echo "$roundtrip_out" | grep -q '"readonly":"sku"' && \
   echo "$roundtrip_out" | grep -q '"max_lengths":"sku=8"'; then
    echo "ok   rich schema round-trip preserved every new metadata key"
else
    echo "FAIL rich schema round-trip lost a metadata key: $roundtrip_out"
    fail=$((fail + 1))
fi

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

assert_code 200 "GET list endpoint" "http://127.0.0.1:$PORT/wal/list/12"
list_out=$(cat /tmp/picowal-test-body)
if echo "$list_out" | grep -q '"pack":12' && \
   echo "$list_out" | grep -q '"records":' && \
   echo "$list_out" | grep -q '"record":101' && \
   echo "$list_out" | grep -q '"data":'; then
    echo "ok   list endpoint output"
else
    echo "FAIL list endpoint output: $list_out"
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
kill "$PID" 2>/dev/null
sleep 0.3
start_server
assert_code 200 "GET persists after restart" "http://127.0.0.1:$PORT/wal/12/999"

# Permissions pack (metadata pack 3 -- RBAC/RLS design metadata). Unlike
# name/schema (packs 1/2), permissions mutations always require credentials
# (api_require_pw_auth), independent of --oidc-cookie-auth, since this is
# new sensitive design surface -- so restart with a write token configured.
kill "$PID" 2>/dev/null
sleep 0.3
TOKEN="picowal-perm-test-token"
start_server --picowal-write-token="$TOKEN"
PH='X-PW-Write-Token: '"$TOKEN"

assert_code 401 "permissions PUT without credentials rejected" -X PUT \
            --data '{"roles":["admin"],"permissions":[],"rowPolicies":[]}' \
            "http://127.0.0.1:$PORT/wal/metadata/permissions/12"
assert_code 204 "permissions PUT with write token" -X PUT -H "$PH" \
            --data '{"roles":["admin","viewer"],"permissions":[{"role":"viewer","pack":12,"actions":["read"]}],"rowPolicies":[{"pack":12,"role":"viewer","predicate":"status|==|Placed"}]}' \
            "http://127.0.0.1:$PORT/wal/metadata/permissions/12"
assert_code 200 "GET permissions" -H "$PH" "http://127.0.0.1:$PORT/wal/metadata/permissions/12"
perm_out=$(cat /tmp/picowal-test-body)
if echo "$perm_out" | grep -q '"roles":\["admin","viewer"\]' && \
   echo "$perm_out" | grep -q '"rowPolicies":' ; then
    echo "ok   permissions output round-trips roles/permissions/rowPolicies"
else
    echo "FAIL permissions output: $perm_out"
    fail=$((fail + 1))
fi

assert_code 200 "GET metadata wrapper includes pack3/permissions" -H "$PH" \
            "http://127.0.0.1:$PORT/wal/metadata/12"
meta3_out=$(cat /tmp/picowal-test-body)
if echo "$meta3_out" | grep -q '"pack3":' && echo "$meta3_out" | grep -q '"permissions":'; then
    echo "ok   metadata wrapper includes pack3 and permissions alias"
else
    echo "FAIL metadata wrapper missing pack3/permissions: $meta3_out"
    fail=$((fail + 1))
fi

assert_code 401 "permissions DELETE without credentials rejected" -X DELETE \
            "http://127.0.0.1:$PORT/wal/metadata/permissions/12"
assert_code 204 "permissions DELETE with write token" -X DELETE -H "$PH" \
            "http://127.0.0.1:$PORT/wal/metadata/permissions/12"
assert_code 404 "GET permissions after delete" -H "$PH" "http://127.0.0.1:$PORT/wal/metadata/permissions/12"

# Auth gate check: when OIDC cookie auth is enabled, /wal routes require
# both X-PW-Auth header and a valid short-lived session cookie.
kill "$PID" 2>/dev/null
sleep 0.3
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
