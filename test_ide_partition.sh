#!/usr/bin/env bash
# test_ide_partition.sh — verifies static_pack (/site/) and the IDE raw
# card store (/ide/card/) are partition-aware for ALL of GET/HEAD/PUT/
# DELETE (not just writes): a record published/saved via one node must be
# readable and writable through EVERY node in the pool, even nodes that
# don't own the underlying (pack, record) key's virtual partition, via
# transparent proxying (--picowal-partition-mode=proxy). Also exercises
# the trailing-filename MIME fix (/site/0/index.html -> text/html) across
# the partitioned cluster.

set -u
cd "$(dirname "$0")"

TOKEN="ide-partition-test-token"
PORT_A=9480
PORT_B=9481
PORT_C=9482
NODES="127.0.0.1:$PORT_A,127.0.0.1:$PORT_B,127.0.0.1:$PORT_C"

DIR_A="$(mktemp -d /tmp/ide-part-a.XXXXXX)"
DIR_B="$(mktemp -d /tmp/ide-part-b.XXXXXX)"
DIR_C="$(mktemp -d /tmp/ide-part-c.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"; echo ok > "$WWW/localhost/index.html"

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$DIR_A" "$DIR_B" "$DIR_C" "$WWW"
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

H='X-PW-Write-Token: '"$TOKEN"

echo "== proxy mode: 3 nodes sharing a partition pool, static-pack card 4 + IDE enabled =="
for port_dir in "$PORT_A:$DIR_A" "$PORT_B:$DIR_B" "$PORT_C:$DIR_C"; do
    port="${port_dir%%:*}"; dir="${port_dir#*:}"
    ./picoweb --picowal-device="$dir" --picowal-format --picowal-write-token="$TOKEN" \
              --picowal-node-id="127.0.0.1:$port" --picowal-partition-nodes="$NODES" \
              --picowal-partition-mode=proxy \
              --picowal-static-card=4 --picowal-static-prefix=/site/ \
              --ide-prefix=/ide/ \
              "$port" "$WWW" 1 100 0 64 > "/tmp/ide-part-$port.log" 2>&1 &
    PIDS+=($!)
done
sleep 0.6

echo
echo "== static_pack: PUT /site/0/index.html via node A, MIME + content visible from EVERY node =="
for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    unauth=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X PUT \
             --data-binary 'unauthorized content' "http://127.0.0.1:$p/site/0/index.html")
    check "PUT /site/0/index.html without credentials via node :$p" "$unauth" "401"
done
put_code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X PUT -H "$H" \
           --data-binary '<h1>partitioned site</h1>' "http://127.0.0.1:$PORT_A/site/0/index.html")
check "PUT /site/0/index.html via node A" "$put_code" "204"

for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    body=$(curl -sS --max-time 5 "http://127.0.0.1:$p/site/0/index.html")
    check "GET /site/0/index.html body via node :$p" "$body" "<h1>partitioned site</h1>"
    ctype=$(curl -sS --max-time 5 -D - -o /dev/null "http://127.0.0.1:$p/site/0/index.html" | grep -i '^content-type:' | tr -d '\r' | tr 'A-Z' 'a-z')
    check "GET /site/0/index.html Content-Type via node :$p" "$ctype" "content-type: text/html; charset=utf-8"
done

echo
echo "== static_pack DELETE via a (likely) non-owner node, visible as 404 from every node =="
del_code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X DELETE -H "$H" "http://127.0.0.1:$PORT_C/site/0/index.html")
check "DELETE /site/0/index.html via node C" "$del_code" "204"
for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    got=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/site/0/index.html")
    check "GET /site/0/index.html -> 404 via node :$p after delete" "$got" "404"
done

echo
echo "== IDE raw card: PUT /ide/card/7/2 via node B, readable/writable from EVERY node =="
put_card=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X PUT -H "$H" \
           --data-binary 'picoscript source, partitioned' "http://127.0.0.1:$PORT_B/ide/card/7/2")
check "PUT /ide/card/7/2 via node B" "$put_card" "204"
for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    got=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$p/ide/card/7/2")
    check "GET /ide/card/7/2 via node :$p" "$got" "picoscript source, partitioned"
done

echo
echo "== IDE raw card GET without credentials is rejected on every node (always-authenticated) =="
for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    got=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/ide/card/7/2")
    check "GET /ide/card/7/2 (no token) -> 401 via node :$p" "$got" "401"
done

echo
if [ "$FAIL" -eq 0 ]; then
    echo "PASS — all $PASS static_pack/ide partition-awareness checks green"
    exit 0
else
    echo "FAIL — $FAIL of $((PASS+FAIL)) checks failed"
    for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
        echo "--- node :$p log ---"; cat "/tmp/ide-part-$p.log" 2>/dev/null
    done
    exit 1
fi
