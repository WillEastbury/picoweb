#!/usr/bin/env bash
# test_ide.sh — single-node smoke test for the hosted PicoScript IDE
# (src/ide.c): the vendored upstream WebIDE portal at GET /ide/, the
# rebuilt PicoWAL workspace at GET /ide/picowal.html, the server bridge
# that wires both to this picoweb instance, the authenticated raw card
# CRUD used to save/load PicoScript source, and the static_pack
# trailing-filename MIME fix (/site/0/index.html -> record 0, Content-Type
# text/html).
# Uses --picowal-write-token (not PicoSTS) since this is a single-node,
# no-external-STS smoke test; see test_picosts_auth.sh for the PicoSTS
# login flow and test_ide_partition.sh for cluster/partition behavior.

set -u
cd "$(dirname "$0")"

TOKEN="ide-smoke-test-token"
PORT=9490

DIR="$(mktemp -d /tmp/ide-smoke.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"; echo ok > "$WWW/localhost/index.html"

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$DIR" "$WWW"
}
trap cleanup EXIT

PASS=0
FAIL=0
check() {
    local desc="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        echo "ok   $desc -> $got"
        PASS=$((PASS+1))
    else
        echo "FAIL $desc -> got '$got' want '$want'"
        FAIL=$((FAIL+1))
    fi
}
contains() {
    local desc="$1" haystack="$2" needle="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "ok   $desc"
        PASS=$((PASS+1))
    else
        echo "FAIL $desc -> '$haystack' does not contain '$needle'"
        FAIL=$((FAIL+1))
    fi
}
not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "ok   $desc"
        PASS=$((PASS+1))
    else
        echo "FAIL $desc -> '$haystack' unexpectedly contains '$needle'"
        FAIL=$((FAIL+1))
    fi
}

H='X-PW-Write-Token: '"$TOKEN"

echo "== starting picoweb with picowal + static-pack + IDE enabled =="
./picoweb --picowal-device="$DIR" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-static-card=1 --picowal-static-prefix=/site/ \
          --picowal-code-card=2 --picowal-code-prefix=/app/ \
          --ide-prefix=/ide/ \
          "$PORT" "$WWW" 1 100 0 64 > /tmp/ide-smoke.log 2>&1 &
PIDS+=($!)
sleep 0.5

echo
echo "== IDE route + compiled-in assets (no filesystem dependency) =="
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/ide/")
check "GET /ide/ -> 200" "$code" "200"
ctype=$(curl -sS -D - -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/ide/" | grep -i '^content-type:' | tr -d '\r')
contains "GET /ide/ Content-Type is HTML" "$ctype" "text/html"
html=$(curl -sS --max-time 5 "http://127.0.0.1:$PORT/ide/")

for asset in pico_hooks.js picoc.js picovm.js baremetal-binary.js; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/ide/$asset")
    check "GET /ide/$asset -> 200" "$code" "200"
done
compile_marker=$(curl -sS --max-time 5 "http://127.0.0.1:$PORT/ide/picoc.js" | grep -c 'PicoCompile')
[ "$compile_marker" -gt 0 ] && { echo "ok   /ide/picoc.js contains PicoCompile"; PASS=$((PASS+1)); } || { echo "FAIL /ide/picoc.js missing PicoCompile"; FAIL=$((FAIL+1)); }
bmb_marker=$(curl -sS --max-time 5 "http://127.0.0.1:$PORT/ide/baremetal-binary.js" | grep -c 'BareMetal.Binary')
[ "$bmb_marker" -gt 0 ] && { echo "ok   /ide/baremetal-binary.js contains BareMetal.Binary"; PASS=$((PASS+1)); } || { echo "FAIL /ide/baremetal-binary.js missing BareMetal.Binary"; FAIL=$((FAIL+1)); }
bmb_ctype=$(curl -sS -D - -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/ide/baremetal-binary.js" | grep -i '^content-type:' | tr -d '\r')
contains "GET /ide/baremetal-binary.js Content-Type is javascript" "$bmb_ctype" "javascript"

echo
echo "== /ide/ is the ACTUAL vendored PicoScript WebIDE portal, not the old hand-rolled shell =="
contains "portal has the real title" "$html" "PicoScript &mdash; IDE, Guide &amp; Reference"
contains "portal has Guide & Reference tab" "$html" "Guide &amp; Reference"
contains "bridge relabels WebIDE as Code Editor" "$html" '"Code Editor"'
contains "portal has Showcase tab" "$html" '&#128295; Showcase'
contains "portal has the file sidebar" "$html" 'id="fileSidebar"'
contains "portal has the file list" "$html" 'id="fileList"'
contains "portal has the Monaco/editor container" "$html" 'id="monaco"'
contains "portal has the textarea fallback editor" "$html" 'id="src"'
contains "portal has Compile & Run" "$html" "Compile &amp; Run"
contains "portal has Compile & Step" "$html" "Compile &amp; Step"
contains "portal has Step" "$html" '>Step<'
contains "portal has Reset" "$html" '>Reset<'
contains "portal has the Disassembly debug panel" "$html" '<h4>Disassembly</h4>'
contains "portal has the Registers debug panel" "$html" '<h4>Registers</h4>'
contains "portal has the Watches debug panel" "$html" '<h4>Watches</h4>'
contains "portal has the dialect/lang toggle" "$html" 'id="langToggle"'
contains "portal has schema designer + Push to live server" "$html" 'schemaPushLive()'
not_contains "portal is NOT the old rejected hand-rolled shell" "$html" 'PicoScript IDE</title>'
not_contains "portal does not still show the old flat PicoWAL-in-editor tab" "$html" 'ws-picowal'

echo
echo "== server bridge wiring (tools/ide_server_bridge.js, injected before </body>) =="
contains "bridge namespace is exposed" "$html" "window.PicoWebBridge"
contains "bridge overrides liveFetch with credentials+X-PW-Auth" "$html" 'X-PW-Auth'
contains "bridge wires live server to config.wal_prefix" "$html" "applyLiveServer"
contains "bridge translates schemas to server-native shape" "$html" "transformSchemaToServerNative"
contains "bridge adds an offline simulator opt-in toggle" "$html" "offline simulator (default is live picowal)"
contains "bridge adds PicoSTS login/logout controls" "$html" '"pwbridge-btn-login"'
contains "bridge adds deploy controls (save source)" "$html" "pwbridgeSaveSource"
contains "bridge adds deploy controls (deploy bytecode)" "$html" "pwbridgeDeployBytecode"
contains "bridge adds deploy controls (publish static)" "$html" "pwbridgePublishStatic"
contains "bridge adds a top-level PicoWAL nav tab" "$html" '"pwbridge-tab-picowal"'
contains "bridge opens PicoWAL as a full portal view" "$html" '"view-picowal"'
contains "bridge uses embedded workspace mode without duplicate chrome" "$html" 'picowal.html?embedded=1'
contains "bridge synchronizes one auth state into the workspace" "$html" "picoweb-auth-state"

echo
echo "== GET /ide/picowal.html serves the rebuilt PicoWAL workspace (separate compiled asset) =="
pw_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/ide/picowal.html")
check "GET /ide/picowal.html -> 200" "$pw_code" "200"
pw_ctype=$(curl -sS -D - -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/ide/picowal.html" | grep -i '^content-type:' | tr -d '\r')
contains "GET /ide/picowal.html Content-Type is HTML" "$pw_ctype" "text/html"
pw_xfo=$(curl -sS -D - -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/ide/picowal.html" | grep -i '^x-frame-options:' | tr -d '\r')
contains "GET /ide/picowal.html allows same-origin framing" "$pw_xfo" "SAMEORIGIN"
pw_html=$(curl -sS --max-time 5 "http://127.0.0.1:$PORT/ide/picowal.html")
contains "workspace has the PicoWAL brand" "$pw_html" "PicoWAL"
contains "workspace supports embedded single-shell mode" "$pw_html" "pwx-embedded"
contains "workspace has Packs & Schemas nav" "$pw_html" "Packs &amp; Schemas"
contains "workspace has a Cards tab panel" "$pw_html" 'id="pw-tab-cards"'
contains "workspace has a Permissions tab panel" "$pw_html" 'id="pw-tab-permissions"'
contains "workspace has a Query tab panel" "$pw_html" 'id="pw-tab-query"'
contains "workspace has a Fast Serial (BSO1) tab panel" "$pw_html" 'id="pw-tab-fastserial"'
contains "workspace documents metadata pack 3 reservation" "$pw_html" "metadata pack 3"
contains "workspace states permissions are not yet enforced" "$pw_html" "does not yet enforce"
contains "workspace wires real /wal/ card CRUD (not /ide/card/)" "$pw_html" 'walFetch(pack + "/" + rec'
contains "workspace has an empty state for the card editor" "$pw_html" 'id="pw-card-empty"'
contains "workspace has PicoSTS login controls" "$pw_html" 'id="pwx-btn-login"'

echo
echo "== rich schema field builder markers (ordinal/maxlen/nullable/readonly/lookup) =="
contains "field builder has ordinal input" "$pw_html" 'id="pw-field-ordinal"'
contains "field builder has max length input" "$pw_html" 'id="pw-field-maxlen"'
contains "field builder has nullable checkbox" "$pw_html" 'id="pw-field-nullable"'
contains "field builder has read-only checkbox" "$pw_html" 'id="pw-field-readonly"'
contains "field builder has lookup pack input" "$pw_html" 'id="pw-field-lookup-pack"'
contains "field builder offers array_u16 type" "$pw_html" '<option>array_u16</option>'
contains "field builder offers blob type" "$pw_html" '<option>blob</option>'
contains "field builder offers lookup type" "$pw_html" '<option>lookup</option>'
contains "field builder offers datetime type" "$pw_html" '<option>datetime</option>'
contains "pack metadata has module input" "$pw_html" 'id="pw-schema-module"'
contains "pack metadata has children input" "$pw_html" 'id="pw-schema-children"'
contains "pack metadata has public-read checkbox" "$pw_html" 'id="pw-schema-public-read"'
contains "lookup dropdown threshold constant present" "$pw_html" 'PW_LOOKUP_DROPDOWN_MAX = 16'

echo
echo "== typed card editor / dirty tracking / child grids markers =="
contains "card editor has visual/raw toggle button" "$pw_html" 'id="pw-card-mode-btn"'
contains "card editor shows version" "$pw_html" 'id="pw-card-version"'
contains "card editor shows dirty fields" "$pw_html" 'id="pw-card-dirty"'
contains "card editor has child grid container" "$pw_html" 'id="pw-card-children"'
contains "child grid logic finds FK back to parent" "$pw_html" "function pwFindChildFkField"
contains "child grid Save All is sequential, not atomic" "$pw_html" "not claimed atomic"

echo
echo "== list search/pagination + MGET markers =="
contains "cards list has client-side search input" "$pw_html" 'id="pw-card-list-search"'
contains "cards list has pager" "$pw_html" 'class="pw-pager"'
contains "cards list paginates 10/page" "$pw_html" "PW_CARDS_PAGE_SIZE = 10"
contains "MGET input present" "$pw_html" 'id="pw-mget-ids"'
contains "MGET fetches concurrently" "$pw_html" "Promise.all(ids.map"

echo
echo "== query builder + client-aggregate markers =="
contains "query tab has FROM packs input" "$pw_html" 'id="pw-qb-from"'
contains "query tab has WHERE op select with IN/NI" "$pw_html" '<option value="NI">NI</option>'
contains "query tab has aggregate function select" "$pw_html" 'id="pw-qb-agg-fn"'
contains "aggregate results are labelled client-computed" "$pw_html" "client-aggregated"

echo
echo "== Fast Serial (BSO1) panel markers =="
contains "fast serial panel has signing key input" "$pw_html" 'id="fs-signing-key"'
contains "fast serial panel derives schema from rich schema" "$pw_html" 'onclick="fsDeriveSchema()"'
contains "fast serial panel has hex preview" "$pw_html" 'id="fs-hex"'
contains "fast serial panel documents parallel binary storage, not queryable" "$pw_html" "not queryable"
contains "fast serial panel uses authenticated partition-aware card endpoint" "$pw_html" 'config.ide_prefix + "card/"'

echo
echo "== permissions principal-role assignments markers =="
contains "permissions tab has assignments table" "$pw_html" 'id="pw-assign-table"'
contains "permissions tab documents assignments are documentation only" "$pw_html" "does not read this"

echo
echo "== GET /ide/config reports issuer/prefix wiring =="
cfg=$(curl -sS --max-time 5 "http://127.0.0.1:$PORT/ide/config")
contains "config reports ide_prefix" "$cfg" '"ide_prefix":"/ide/"'
contains "config reports wal_prefix" "$cfg" '"wal_prefix":"/wal/"'
contains "config reports static_prefix" "$cfg" '"static_prefix":"/site/"'
contains "config reports code_prefix" "$cfg" '"code_prefix":"/app/"'
contains "config reports picosts disabled (not configured)" "$cfg" '"picosts_enabled":false'

echo
echo "== authenticated raw card CRUD: save/load PicoScript source =="
put_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X PUT -H "$H" \
           --data-binary 'func main() { return 200; }' "http://127.0.0.1:$PORT/ide/card/9/1")
check "PUT /ide/card/9/1 (save source) -> 204" "$put_code" "204"
loaded=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PORT/ide/card/9/1")
check "GET /ide/card/9/1 (load source) round-trips" "$loaded" "func main() { return 200; }"
no_auth=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/ide/card/9/1")
check "GET /ide/card/9/1 without credentials -> 401" "$no_auth" "401"
del_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X DELETE -H "$H" "http://127.0.0.1:$PORT/ide/card/9/1")
check "DELETE /ide/card/9/1 -> 204" "$del_code" "204"
after_del=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -H "$H" "http://127.0.0.1:$PORT/ide/card/9/1")
check "GET /ide/card/9/1 after delete -> 404" "$after_del" "404"

echo
echo "== static_pack trailing-filename MIME fix (/site/{record}/{filename}) =="
curl -sS -o /dev/null --max-time 5 -X PUT -H "$H" --data-binary '<h1>hi</h1>' "http://127.0.0.1:$PORT/site/0/index.html" >/dev/null
ctype=$(curl -sS -D - -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/site/0/index.html" | grep -i '^content-type:' | tr -d '\r' | tr 'A-Z' 'a-z')
check "GET /site/0/index.html Content-Type" "$ctype" "content-type: text/html; charset=utf-8"
curl -sS -o /dev/null --max-time 5 -X PUT -H "$H" --data-binary 'console.log(1);' "http://127.0.0.1:$PORT/site/1/app.js" >/dev/null
ctype2=$(curl -sS -D - -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/site/1/app.js" | grep -i '^content-type:' | tr -d '\r' | tr 'A-Z' 'a-z')
contains "GET /site/1/app.js Content-Type is javascript" "$ctype2" "javascript"
# legacy "{record}.ext" form still works (preserved, not regressed)
ctype3=$(curl -sS -D - -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/site/0.html" | grep -i '^content-type:' | tr -d '\r' | tr 'A-Z' 'a-z')
check "GET /site/0.html (legacy form) Content-Type" "$ctype3" "content-type: text/html; charset=utf-8"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "PASS — all $PASS IDE smoke checks green"
    exit 0
else
    echo "FAIL — $FAIL of $((PASS+FAIL)) checks failed"
    echo "--- server log ---"; cat /tmp/ide-smoke.log
    exit 1
fi
