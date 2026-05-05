#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
pkill -9 picoweb 2>/dev/null || true
sleep 1
./picoweb 18080 wwwroot 4 0 >/tmp/ms.log 2>&1 &
SVR=$!
sleep 1

PIDS=""
for i in 1 2 3 4; do
    ./bench 18080 64 15 / localhost > /tmp/b$i.log 2>&1 &
    PIDS="$PIDS $!"
done
for p in $PIDS; do wait $p; done

pkill -9 picoweb 2>/dev/null || true
sleep 0.3

echo "--- per-client ---"
for i in 1 2 3 4; do
    grep -E '^conns=' /tmp/b$i.log
done
echo "--- aggregate ---"
awk '
    /^conns=/ {
        for (k = 1; k <= NF; k++) {
            split($k, kv, "=")
            if (kv[1] == "rps") r += kv[2]
            if (kv[1] == "throughput") t += kv[2]
        }
    }
    END { printf "agg_rps=%d  agg_throughput_MiB=%.1f\n", r, t }
' /tmp/b1.log /tmp/b2.log /tmp/b3.log /tmp/b4.log
