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
          "$PPORT" "$WWW" 1 100 0 64 > /tmp/bench-primary.log 2>&1 &
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
          "$R1PORT" "$WWW" 1 100 0 64 > /tmp/bench-replica1.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$R2DIR" --picowal-format \
          --picowal-write-token="$TOKEN" \
          --picowal-replica-of="http://127.0.0.1:$PPORT/repl/" \
          "$R2PORT" "$WWW" 1 100 0 64 > /tmp/bench-replica2.log 2>&1 &
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

writer() {
    local id="$1" n="$2" ok=0 err=0
    for i in $(seq 1 "$n"); do
        local rec=$((id * 10000 + i))
        code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X PUT -H "$H" \
               --data-binary "{\"id\":\"i$rec\",\"name\":\"item-$rec\",\"value\":$rec}" \
               "http://127.0.0.1:$PPORT/wal/10/$rec")
        if [ "$code" = "204" ]; then ok=$((ok+1)); else err=$((err+1)); fi
    done
    echo "$ok $err" > "$WORK/write-$id.result"
}

reader() {
    local id="$1" n="$2" ok=0 err=0 port
    for i in $(seq 1 "$n"); do
        # round-robin across the two replicas; alternate GET / query / report
        port=$(( (i % 2 == 0) ? R1PORT : R2PORT ))
        case $((i % 3)) in
            0)
                code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -H "$H" \
                       "http://127.0.0.1:$port/wal/10/$(( (id*10000)+ (i%150)+1 ))")
                ;;
            1)
                code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X POST -H "$H" \
                       --data-binary $'S:name,value\nF:10\nW:value|>|0' \
                       "http://127.0.0.1:$port/wal/query")
                ;;
            *)
                code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X POST -H "$H" \
                       --data-binary $'S:name,value\nF:10\nW:value|>|0' \
                       "http://127.0.0.1:$port/wal/report")
                ;;
        esac
        if [[ "$code" == 2* ]]; then ok=$((ok+1)); else err=$((err+1)); fi
    done
    echo "$ok $err" > "$WORK/read-$id.result"
}

echo "== phase 1: $WRITE_WORKERS writers x $WRITES_PER_WORKER writes to primary =="
t0=$(date +%s.%N)
WJOBS=()
for w in $(seq 1 "$WRITE_WORKERS"); do
    writer "$w" "$WRITES_PER_WORKER" &
    WJOBS+=($!)
done
wait "${WJOBS[@]}"
t1=$(date +%s.%N)

w_ok=0; w_err=0
for f in "$WORK"/write-*.result; do
    read -r a b < "$f"
    w_ok=$((w_ok + a)); w_err=$((w_err + b))
done
w_total=$((w_ok + w_err))
w_elapsed=$(echo "$t1 - $t0" | bc)
w_rps=$(echo "scale=1; $w_total / $w_elapsed" | bc)

echo "writes: $w_ok ok, $w_err err, ${w_elapsed}s elapsed, ${w_rps} req/s"

echo "== phase 2: $READ_WORKERS readers x $READS_PER_WORKER reads/queries/reports across replicas =="
t0=$(date +%s.%N)
RJOBS=()
for r in $(seq 1 "$READ_WORKERS"); do
    reader "$r" "$READS_PER_WORKER" &
    RJOBS+=($!)
done
wait "${RJOBS[@]}"
t1=$(date +%s.%N)

r_ok=0; r_err=0
for f in "$WORK"/read-*.result; do
    read -r a b < "$f"
    r_ok=$((r_ok + a)); r_err=$((r_err + b))
done
r_total=$((r_ok + r_err))
r_elapsed=$(echo "$t1 - $t0" | bc)
r_rps=$(echo "scale=1; $r_total / $r_elapsed" | bc)

echo "reads:  $r_ok ok, $r_err err, ${r_elapsed}s elapsed, ${r_rps} req/s"

echo
echo "== phase 3: replica consistency check =="
last_rec=$(( WRITE_WORKERS * 10000 + WRITES_PER_WORKER ))
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

echo
echo "== summary =="
echo "primary writes:  $w_total total, ${w_rps} req/s, $w_err errors"
echo "replica reads:   $r_total total, ${r_rps} req/s, $r_err errors"
