#!/usr/bin/env bash
# test_pico_route_partition.sh — verifies that PicoScript's Storage.* hooks
# (pico_route.c) are partition-aware: a card added/read via one node must be
# reachable through EVERY node in the pool, even nodes that don't own the
# underlying (pack, record) key, by transparently forwarding over the
# internal "{prefix}_raw/{pack}/{rec}" endpoint to the true owner.

set -u
cd "$(dirname "$0")"

TOKEN="pico-route-partition-token"
PORT_A=9280
PORT_B=9281
PORT_C=9282
NODES="127.0.0.1:$PORT_A,127.0.0.1:$PORT_B,127.0.0.1:$PORT_C"

DIR_A="$(mktemp -d /tmp/pr-part-a.XXXXXX)"
DIR_B="$(mktemp -d /tmp/pr-part-b.XXXXXX)"
DIR_C="$(mktemp -d /tmp/pr-part-c.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"; echo ok > "$WWW/localhost/index.html"

BYTECODE=/tmp/pr-router.bin
PICOSCRIPT_DIR="../picoscript"
if [ ! -d "$PICOSCRIPT_DIR" ]; then PICOSCRIPT_DIR="$(dirname "$0")/../picoscript"; fi
python3 "$PICOSCRIPT_DIR/picoscript_build.py" emit "$PICOSCRIPT_DIR/host/picowal/router.eng" \
    --as bytecode --hex 2>/dev/null | python3 "$(dirname "$0")/hex_to_bin.py" > "$BYTECODE"
if [ ! -s "$BYTECODE" ]; then
    echo "FAIL could not compile host/picowal/router.eng -- is $PICOSCRIPT_DIR checked out?"
    exit 1
fi

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

echo "== proxy mode: 3 nodes sharing a partition pool, PicoScript router deployed on code card 6 =="
./picoweb --picowal-device="$DIR_A" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_A" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          --picowal-code-card=6 --picowal-code-prefix=/app/ \
          "$PORT_A" "$WWW" 1 100 0 64 > /tmp/pr-part-a.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$DIR_B" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_B" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          --picowal-code-card=6 --picowal-code-prefix=/app/ \
          "$PORT_B" "$WWW" 1 100 0 64 > /tmp/pr-part-b.log 2>&1 &
PIDS+=($!)
./picoweb --picowal-device="$DIR_C" --picowal-format --picowal-write-token="$TOKEN" \
          --picowal-node-id="127.0.0.1:$PORT_C" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          --picowal-code-card=6 --picowal-code-prefix=/app/ \
          "$PORT_C" "$WWW" 1 100 0 64 > /tmp/pr-part-c.log 2>&1 &
PIDS+=($!)
sleep 0.6

# Deploy the same bytecode to all 3 nodes (each has its own independent
# code-card volume -- deployment itself isn't a partitioned operation).
for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    dep_code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X PUT -H "$H" \
               --data-binary @"$BYTECODE" "http://127.0.0.1:$p/app/")
    check "deploy router bytecode to node :$p" "$dep_code" "204"
done

echo
echo "== Storage.AddCard via node A, Storage.ReadCard via EVERY node (including non-owners) =="
post_resp=$(curl -sS --max-time 5 -X POST --data-binary "hello-partitioned-world" \
            "http://127.0.0.1:$PORT_A/app/create")
check "POST /app (Storage.AddCard) via node A" "$post_resp" "created"

for p in "$PORT_A" "$PORT_B" "$PORT_C"; do
    got=$(curl -sS --max-time 5 "http://127.0.0.1:$p/app/0")
    check "GET /app/0 (Storage.ReadCard) via node :$p sees the card" "$got" "hello-partitioned-world"
done

echo
if [ "$FAIL" -eq 0 ]; then
    echo "PASS — all $PASS pico_route partition-awareness checks green"
    exit 0
else
    echo "FAIL — $FAIL of $((PASS+FAIL)) checks failed"
    exit 1
fi
