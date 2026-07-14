#!/usr/bin/env bash
# test_picowal_partition.sh — verifies virtual-partition ownership routing
# added on top of picowal's single-volume /wal/ record CRUD:
#   - 1000 virtual partitions, rendezvous(HRW)-hashed over a node pool
#   - a write landing on a non-owner node is either redirected (307) or
#     transparently proxied to the owner, depending on --picowal-partition-mode
#   - every node computes the SAME owner independently (no coordination)
#   - a record written via any node in the pool is retrievable from the
#     owner directly

set -u
cd "$(dirname "$0")"

TOKEN="partition-test-token"
PORT_A=9180
PORT_B=9181
PORT_C=9182
NODES="127.0.0.1:$PORT_A,127.0.0.1:$PORT_B,127.0.0.1:$PORT_C"

DIR_A="$(mktemp -d /tmp/part-a.XXXXXX)"
DIR_B="$(mktemp -d /tmp/part-b.XXXXXX)"
DIR_C="$(mktemp -d /tmp/part-c.XXXXXX)"
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

echo "== redirect mode: starting 3 nodes sharing the same partition pool =="
./picoweb --picowal-device="$DIR_A" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_A" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=redirect \
          "$PORT_A" "$WWW" 1 100 0 64 > /tmp/part-a.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$DIR_B" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_B" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=redirect \
          "$PORT_B" "$WWW" 1 100 0 64 > /tmp/part-b.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$DIR_C" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_C" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=redirect \
          "$PORT_C" "$WWW" 1 100 0 64 > /tmp/part-c.log 2>&1 &
PIDS+=($!)
sleep 0.6

curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" --data-binary '{"name":"items"}' \
     "http://127.0.0.1:$PORT_A/wal/metadata/name/10"
curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" \
     --data-binary '{"fields":"id,name,value","required":"id,name","types":"id=string;name=string;value=number"}' \
     "http://127.0.0.1:$PORT_A/wal/metadata/schema/10"
# schema was only written on node A directly (no replication between these
# 3 independent volumes -- partitioning here is orthogonal to whole-volume
# replication); write metadata/name+schema on B and C too so validation
# passes regardless of which node ends up owning a given record.
for p in "$PORT_B" "$PORT_C"; do
    curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" --data-binary '{"name":"items"}' \
         "http://127.0.0.1:$p/wal/metadata/name/10"
    curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" \
         --data-binary '{"fields":"id,name,value","required":"id,name","types":"id=string;name=string;value=number"}' \
         "http://127.0.0.1:$p/wal/metadata/schema/10"
done

echo
echo "== ownership agreement: same record must resolve to the same owner from every node =="
# Find a record id whose owner is NOT node A, to exercise redirect.
rec=""
owner_expect=""
for i in $(seq 1 200); do
    resp=$(curl -sS --max-time 5 -D - -o /dev/null -X PUT -H "$H" \
           --data-binary "{\"id\":\"i$i\",\"name\":\"item-$i\",\"value\":$i}" \
           "http://127.0.0.1:$PORT_A/wal/10/$i")
    code=$(echo "$resp" | head -1 | tr -d '\r\n')
    if echo "$code" | grep -q "307"; then
        owner_expect=$(echo "$resp" | grep -i '^X-PW-Partition-Owner:' | awk '{print $2}' | tr -d '\r')
        rec="$i"
        break
    fi
done
if [ -z "$rec" ]; then
    echo "FAIL could not find a record redirected away from node A in 200 tries"
    FAIL=$((FAIL+1))
else
    echo "ok   record $rec redirects from node A to owner $owner_expect"
    PASS=$((PASS+1))

    # ask B and C directly (not via A) what THEY think the owner is for
    # the same record -- must agree, since ownership is a pure function
    # of (tenant node-set, vpart), computed identically everywhere.
    for p in "$PORT_B" "$PORT_C"; do
        resp=$(curl -sS --max-time 5 -D - -o /dev/null -X PUT -H "$H" \
               --data-binary "{\"id\":\"i$rec\",\"name\":\"item-$rec\",\"value\":$rec}" \
               "http://127.0.0.1:$p/wal/10/$rec")
        code=$(echo "$resp" | head -1 | awk '{print $2}')
        if [ "$code" = "307" ]; then
            owner_got=$(echo "$resp" | grep -i '^X-PW-Partition-Owner:' | awk '{print $2}' | tr -d '\r')
        else
            owner_got="127.0.0.1:$p"
        fi
        check "node :$p agrees on owner for record $rec" "$owner_got" "$owner_expect"
    done

    echo
    echo "== write to the resolved owner directly, then read it back =="
    owner_port="${owner_expect##*:}"
    put_code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X PUT -H "$H" \
               --data-binary "{\"id\":\"i$rec\",\"name\":\"item-$rec\",\"value\":$rec}" \
               "http://127.0.0.1:$owner_port/wal/10/$rec")
    check "PUT directly to owner :$owner_port" "$put_code" "204"
    got_body=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$owner_port/wal/10/$rec")
    check "GET from owner reflects the write" "$(echo "$got_body" | grep -c "item-$rec")" "1"

    echo
    echo "== query gateway: /wal/query fans out to every node in the pool, merges rows =="
    # Records i1..i$rec were written above (before the redirect was hit, each
    # PUT lands on whichever node happens to own that id) so they are spread
    # across all 3 nodes' independent volumes. A query sent to ANY single
    # node must return the union of every node's local rows, not just its own.
    query_body=$'S:id,name,value\nF:10'
    counts=()
    for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
        out=$(curl -sS --max-time 5 -X POST --data-binary "$query_body" -H "$H" \
              "http://127.0.0.1:$p/wal/query")
        c=$(echo "$out" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2)
        counts+=("$c")
    done
    check "node A/B/C query counts agree" "${counts[0]}=${counts[1]}=${counts[2]}" \
          "${counts[0]}=${counts[0]}=${counts[0]}"
    check "query gateway merged count covers all $rec written records" \
          "$([ "${counts[0]:-0}" -ge "$rec" ] && echo yes || echo no)" "yes"
fi

echo
echo "== proxy mode: non-owner transparently forwards, response carries proxy headers =="
for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
wait 2>/dev/null
PIDS=()
rm -rf "$DIR_A" "$DIR_B" "$DIR_C"
DIR_A="$(mktemp -d /tmp/part-a.XXXXXX)"
DIR_B="$(mktemp -d /tmp/part-b.XXXXXX)"
DIR_C="$(mktemp -d /tmp/part-c.XXXXXX)"

./picoweb --picowal-device="$DIR_A" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_A" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          "$PORT_A" "$WWW" 1 100 0 64 > /tmp/part-a2.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$DIR_B" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_B" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          "$PORT_B" "$WWW" 1 100 0 64 > /tmp/part-b2.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$DIR_C" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_C" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          "$PORT_C" "$WWW" 1 100 0 64 > /tmp/part-c2.log 2>&1 &
PIDS+=($!)
sleep 0.6

for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" --data-binary '{"name":"items"}' \
         "http://127.0.0.1:$p/wal/metadata/name/10"
    curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" \
         --data-binary '{"fields":"id,name,value","required":"id,name","types":"id=string;name=string;value=number"}' \
         "http://127.0.0.1:$p/wal/metadata/schema/10"
done

put_resp=$(curl -sS --max-time 5 -D - -o /tmp/part-proxy-body -X PUT -H "$H" \
           --data-binary "{\"id\":\"i$rec\",\"name\":\"proxied-$rec\",\"value\":$rec}" \
           "http://127.0.0.1:$PORT_A/wal/10/$rec")
put_code=$(echo "$put_resp" | head -1 | awk '{print $2}')
check "proxied PUT to node A returns owner's status" "$put_code" "204"
has_proxy_hdr=$(echo "$put_resp" | grep -ic '^X-PW-Proxied-From:')
check "proxied response carries X-PW-Proxied-From" "$has_proxy_hdr" "1"

# confirm it actually landed on the owner's volume (query it directly)
owner_port="${owner_expect##*:}"
got_body=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$owner_port/wal/10/$rec")
check "record actually stored on owner volume via proxy" "$(echo "$got_body" | grep -c "proxied-$rec")" "1"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "PASS — all $PASS partition-routing checks green"
    exit 0
else
    echo "FAIL — $FAIL of $((PASS+FAIL)) checks failed"
    exit 1
fi
