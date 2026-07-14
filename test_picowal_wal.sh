#!/usr/bin/env bash
# test_picowal_wal.sh — exercise the picowal WAL/base.dat storage engine
# directly: multi-segment WAL rotation, checkpoint folding, and
# segment-aware primary/replica replication across a rotation event.
#
# This test targets the storage engine itself (not the JSON/schema layer
# covered by test_picowal.sh), so it drives the raw /wal/{card}/{record}
# byte routes and the /repl/* replication feed.

set -u
cd "$(dirname "$0")"

PPORT="${1:-8790}"
RPORT="${2:-8791}"
TOKEN="picowal-wal-test-token"

PDIR="$(mktemp -d /tmp/picowal-wal-primary.XXXXXX)"
RDIR="$(mktemp -d /tmp/picowal-wal-replica.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"
echo '<h1>hi</h1>' > "$WWW/localhost/index.html"

PWPID=""
RPID=""
cleanup() {
    [ -n "$PWPID" ] && kill "$PWPID" 2>/dev/null
    [ -n "$RPID" ] && kill "$RPID" 2>/dev/null
    wait "$PWPID" "$RPID" 2>/dev/null
    rm -rf "$PDIR" "$RDIR" "$WWW"
}
trap cleanup EXIT

fail=0
pass() { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=$((fail + 1)); }

start_primary() {
    ./picoweb --picowal-device="$PDIR" --picowal-format \
              --picowal-bytes=8192 \
              --picowal-write-token="$TOKEN" \
              --picowal-repl --picowal-repl-prefix=/repl/ \
              "$@" "$PPORT" "$WWW" 1 100 0 64 \
              > /tmp/picowal-wal-primary.log 2>&1 &
    PWPID=$!
    sleep 0.4
}

start_replica() {
    ./picoweb --picowal-device="$RDIR" --picowal-format \
              --picowal-bytes=8192 \
              --picowal-write-token="$TOKEN" \
              --picowal-replica-of="http://127.0.0.1:$PPORT/repl/" \
              "$RPORT" "$WWW" 1 100 0 64 \
              > /tmp/picowal-wal-replica.log 2>&1 &
    RPID=$!
    sleep 0.4
}

wait_for() {
    # wait_for URL EXPECT_SUBSTR TIMEOUT_SEC
    local url="$1" expect="$2" timeout="${3:-10}"
    local start=$SECONDS
    while (( SECONDS - start < timeout )); do
        local body
        body=$(curl -sS --max-time 2 -H "X-PW-Write-Token: $TOKEN" "$url" 2>/dev/null)
        if [[ "$body" == *"$expect"* ]]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# ---- 1. basic put/get on the new engine ----
start_primary

code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H "X-PW-Write-Token: $TOKEN" \
       --data-binary 'hello-wal-engine' "http://127.0.0.1:$PPORT/wal/1/1")
[ "$code" = "204" ] && pass "PUT record -> 204" || bad "PUT record -> $code"

body=$(curl -sS -H "X-PW-Write-Token: $TOKEN" "http://127.0.0.1:$PPORT/wal/1/1")
[ "$body" = "hello-wal-engine" ] && pass "GET record roundtrip" || bad "GET record roundtrip: got '$body'"

# ---- 2. force multiple WAL segment rotations (segment_bytes=8192, ~16 512B records/segment) ----
for i in $(seq 1 40); do
    payload=$(printf 'x%.0s' $(seq 1 500))
    curl -sS -o /dev/null -X PUT -H "X-PW-Write-Token: $TOKEN" \
         --data-binary "$payload" "http://127.0.0.1:$PPORT/wal/2/$i"
done

seg_json=$(curl -sS -H "X-PW-Write-Token: $TOKEN" "http://127.0.0.1:$PPORT/repl/segments")
sealed_count=$(echo "$seg_json" | grep -o '"sealed":true' | wc -l)
if [ "$sealed_count" -ge 2 ]; then
    pass "WAL rotation produced >=2 sealed segments ($sealed_count)"
else
    bad "WAL rotation expected >=2 sealed segments, got $sealed_count: $seg_json"
fi

# a record written into an early (now-sealed) segment must still read back
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-PW-Write-Token: $TOKEN" "http://127.0.0.1:$PPORT/wal/2/1")
[ "$code" = "200" ] && pass "read record from sealed (rotated-away) segment" \
                     || bad "read record from sealed segment -> $code"

status_json=$(curl -sS -H "X-PW-Write-Token: $TOKEN" "http://127.0.0.1:$PPORT/repl/status")
echo "$status_json" | grep -q '"leading_wal_id"' && pass "repl status reports leading_wal_id" \
                                                  || bad "repl status missing leading_wal_id: $status_json"

# ---- 3. persistence across restart (WAL + base.dat both reloaded correctly) ----
kill "$PWPID" 2>/dev/null; wait "$PWPID" 2>/dev/null; PWPID=""
sleep 0.3
start_primary
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-PW-Write-Token: $TOKEN" "http://127.0.0.1:$PPORT/wal/2/40")
[ "$code" = "200" ] && pass "record from rotated segment survives restart" \
                     || bad "record from rotated segment survives restart -> $code"

# ---- 4. end-to-end replica catch-up across a rotation boundary ----
start_replica
if wait_for "http://127.0.0.1:$RPORT/wal/1/1" "hello-wal-engine" 10; then
    pass "replica caught up on pre-existing base.dat/sealed-segment data"
else
    bad "replica never caught up on pre-existing data"
fi

# write more on the primary *after* the replica has joined, forcing another
# rotation while the replica is actively following the leading segment
for i in $(seq 41 60); do
    payload=$(printf 'y%.0s' $(seq 1 500))
    curl -sS -o /dev/null -X PUT -H "X-PW-Write-Token: $TOKEN" \
         --data-binary "$payload" "http://127.0.0.1:$PPORT/wal/2/$i"
done

if wait_for "http://127.0.0.1:$RPORT/wal/2/55" "y" 10; then
    pass "replica caught up across a post-join rotation"
else
    bad "replica did not catch up across a post-join rotation"
fi

# replica must refuse local writes
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H "X-PW-Write-Token: $TOKEN" \
       --data-binary 'nope' "http://127.0.0.1:$RPORT/wal/9/999")
[ "$code" = "503" ] && pass "replica refuses local writes -> 503" || bad "replica refuses local writes -> $code"

echo
if [ $fail -eq 0 ]; then
    echo "PASS — all picowal WAL-engine tests green"
    exit 0
else
    echo "FAIL — $fail test(s) failed"
    echo "--- primary log tail ---"
    tail -30 /tmp/picowal-wal-primary.log
    echo "--- replica log tail ---"
    tail -30 /tmp/picowal-wal-replica.log
    exit 1
fi
