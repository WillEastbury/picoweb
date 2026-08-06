#!/usr/bin/env bash
# test_picowal_partition.sh — verifies virtual-partition ownership routing
# added on top of picowal's single-volume /wal/ record CRUD:
#   - 1000 virtual partitions, rendezvous(HRW)-hashed over a node pool
#   - a write landing on a non-owner node is either redirected (307) or
#     transparently proxied to the owner, depending on --picowal-partition-mode
#   - every node computes the SAME owner independently (no coordination)
#   - a record written via any node in the pool is retrievable from the
#     owner directly
#   - metadata packs (name/schema/permissions -- packs 1/2/3) are replicated
#     to every node in the pool on PUT/DELETE, unlike per-record data (which
#     is sharded by ownership), so metadata mutated through any one node
#     reads back identically from every other node
#   - GET /wal/list/{pack} fans out to every node and merges + de-duplicates
#     records, the same way /wal/query already does
#   - metadata mutations (permissions pack specifically) are rejected
#     without credentials, on every node in the pool

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
curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" \
     --data-binary '{"roles":["admin","viewer"],"permissions":[{"role":"viewer","pack":10,"actions":["read"]}],"rowPolicies":[]}' \
     "http://127.0.0.1:$PORT_A/wal/metadata/permissions/10"

echo
echo "== metadata replication: name/schema/permissions written through node A are readable on B and C =="
# Metadata packs (name/schema/permissions) are replicated to every node in
# the tenant's partition pool on PUT/DELETE (unlike per-record data, which
# is sharded by ownership) -- so a mutation applied through any single node
# must be visible on every other node without writing it there again.
name_b=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PORT_B/wal/metadata/name/10")
check "node B sees name written via node A" "$(echo "$name_b" | grep -c '"items"')" "1"
schema_c=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PORT_C/wal/metadata/schema/10")
check "node C sees schema written via node A" "$(echo "$schema_c" | grep -c '"fields":"id,name,value"')" "1"
perm_b=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PORT_B/wal/metadata/permissions/10")
check "node B sees permissions written via node A" "$(echo "$perm_b" | grep -c '"role":"viewer"')" "1"
meta_c=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PORT_C/wal/metadata/10")
check "node C combined metadata wrapper includes pack3/permissions" \
      "$(echo "$meta_c" | grep -c '"pack3":' )=$(echo "$meta_c" | grep -c '"permissions":')" "1=1"

echo
echo "== unauthenticated metadata mutations are rejected (permissions pack always requires credentials) =="
noauth_code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X PUT \
              --data-binary '{"roles":[]}' "http://127.0.0.1:$PORT_A/wal/metadata/permissions/11")
check "PUT permissions without credentials -> 401" "$noauth_code" "401"
noauth_del=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X DELETE \
             "http://127.0.0.1:$PORT_B/wal/metadata/permissions/10")
check "DELETE permissions without credentials -> 401" "$noauth_del" "401"
# Confirm the (unauthenticated, thus rejected) delete attempt above did NOT
# remove the record -- a rejected mutation must not partially apply either
# locally or via replication.
still_there=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -H "$H" \
              "http://127.0.0.1:$PORT_C/wal/metadata/permissions/10")
check "permissions record untouched by rejected delete" "$still_there" "200"

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

    echo
    echo "== list gateway: GET /wal/list/10 fans out and merges records from every node =="
    # Same records i1..i$rec are spread across all 3 nodes' independent
    # volumes (ownership routing sent each PUT to whichever node owns that
    # id) -- GET /wal/list/{pack} through ANY single node must merge them
    # all, de-duplicated by record id, not just return its own local shard.
    list_counts=()
    list_bodies=()
    for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
        out=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$p/wal/list/10")
        c=$(echo "$out" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2)
        list_counts+=("$c")
        list_bodies+=("$out")
    done
    check "node A/B/C list counts agree" "${list_counts[0]}=${list_counts[1]}=${list_counts[2]}" \
          "${list_counts[0]}=${list_counts[0]}=${list_counts[0]}"
    check "list gateway merged count covers all $rec written records" \
          "$([ "${list_counts[0]:-0}" -ge "$rec" ] && echo yes || echo no)" "yes"
    dup_check=$(echo "${list_bodies[0]}" | grep -o '"record":[0-9]*' | sort | uniq -d | wc -l)
    check "list gateway de-duplicates records (no repeats)" "$dup_check" "0"
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

echo
echo "== metadata replication also works in proxy mode: one write, readable everywhere =="
curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" --data-binary '{"name":"widgets"}' \
     "http://127.0.0.1:$PORT_B/wal/metadata/name/20"
name_a=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PORT_A/wal/metadata/name/20")
check "node A sees name written via node B (proxy mode)" "$(echo "$name_a" | grep -c 'widgets')" "1"
name_c=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PORT_C/wal/metadata/name/20")
check "node C sees name written via node B (proxy mode)" "$(echo "$name_c" | grep -c 'widgets')" "1"

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
