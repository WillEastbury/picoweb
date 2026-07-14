#!/usr/bin/env bash
# bench_cluster.sh — spin up a small picowal "cluster" (1 primary + 2 read
# replicas), seed a data-driven CRUD/query/report pack, then hammer it with
# concurrent writers (primary) and readers/queriers/reporters (replicas) to
# get a rough throughput number.
#
# Keep-it-simple v1: no gossip/election here, just primary + replicas.

set -u
cd "$(dirname "$0")"

TOKEN="bench-cluster-token"
PPORT=9080
R1PORT=9081
R2PORT=9082

PDIR="$(mktemp -d /tmp/bench-primary.XXXXXX)"
R1DIR="$(mktemp -d /tmp/bench-replica1.XXXXXX)"
R2DIR="$(mktemp -d /tmp/bench-replica2.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"
echo ok > "$WWW/localhost/index.html"

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$PDIR" "$R1DIR" "$R2DIR" "$WWW" /tmp/bench-work
}
trap cleanup EXIT

H='X-PW-Write-Token: '"$TOKEN"

echo "== starting primary :$PPORT =="
./picoweb --picowal-device="$PDIR" --picowal-format \
          --picowal-write-token="$TOKEN" \
          --picowal-repl --picowal-repl-prefix=/repl/ \
          "$PPORT" "$WWW" 4 100 0 64 > /tmp/bench-primary.log 2>&1 &
PIDS+=($!)
sleep 0.5

echo "== seeding pack 10 ('items') schema =="
curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" --data-binary '{"name":"items"}' \
     "http://127.0.0.1:$PPORT/wal/metadata/name/10"
curl -sS --max-time 5 -o /dev/null -X PUT -H "$H" \
     --data-binary '{"fields":"id,name,value","required":"id,name","types":"id=string;name=string;value=number"}' \
     "http://127.0.0.1:$PPORT/wal/metadata/schema/10"

echo "== starting replicas :$R1PORT :$R2PORT =="
./picoweb --picowal-device="$R1DIR" --picowal-format \
          --picowal-write-token="$TOKEN" \
          --picowal-replica-of="http://127.0.0.1:$PPORT/repl/" \
          "$R1PORT" "$WWW" 4 100 0 64 > /tmp/bench-replica1.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$R2DIR" --picowal-format \
          --picowal-write-token="$TOKEN" \
          --picowal-replica-of="http://127.0.0.1:$PPORT/repl/" \
          "$R2PORT" "$WWW" 4 100 0 64 > /tmp/bench-replica2.log 2>&1 &
PIDS+=($!)
sleep 0.6

# wait for replicas to see the seeded schema before benchmarking reads
for port in "$R1PORT" "$R2PORT"; do
    for _ in $(seq 1 30); do
        body=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$port/wal/metadata/name/10" 2>/dev/null)
        [[ "$body" == *items* ]] && break
        sleep 0.2
    done
done
echo "== replicas caught up on schema =="

WORK=/tmp/bench-work
rm -rf "$WORK"; mkdir -p "$WORK"

WRITE_WORKERS=16
WRITES_PER_WORKER=300
READ_WORKERS=16
READS_PER_WORKER=300

# bench_load.py uses persistent (keep-alive) connections per worker thread
# instead of spawning a new curl process per request, so the numbers below
# reflect picoweb's actual request handling rather than TCP-handshake /
# process-spawn overhead.
python3 bench_load.py \
    --write-port "$PPORT" --read-ports "$R1PORT" "$R2PORT" \
    --token "$TOKEN" --pack 10 \
    --write-workers "$WRITE_WORKERS" --writes-per-worker "$WRITES_PER_WORKER" \
    --read-workers "$READ_WORKERS" --reads-per-worker "$READS_PER_WORKER"
py_rc=$?

echo
echo "== phase 3: replica consistency check =="
last_rec=$(( (WRITE_WORKERS - 1) * 10000 + WRITES_PER_WORKER - 1 ))
sleep 0.5
p_body=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$PPORT/wal/10/$last_rec")
for port in "$R1PORT" "$R2PORT"; do
    rep_body=""
    for _ in $(seq 1 30); do
        rep_body=$(curl -sS --max-time 5 -H "$H" "http://127.0.0.1:$port/wal/10/$last_rec" 2>/dev/null)
        [ "$rep_body" = "$p_body" ] && break
        sleep 0.2
    done
    if [ "$rep_body" = "$p_body" ]; then
        echo "ok   replica :$port matches primary for last written record"
    else
        echo "FAIL replica :$port DIVERGED (primary='$p_body' replica='$rep_body')"
    fi
done

exit "$py_rc"
