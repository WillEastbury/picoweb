#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
pkill -9 picoweb 2>/dev/null || true
sleep 0.3
./picoweb 8080 ./wwwroot 8 > /tmp/m.log 2>&1 &
SVR=$!
sleep 0.5
echo "=== 4 parallel bench clients × 64 conns × 20s ==="
PIDS=""
for i in 1 2 3 4; do
    ./bench 8080 64 20 / localhost > /tmp/b$i.log &
    PIDS="$PIDS $!"
done
for p in $PIDS; do wait $p; done
for i in 1 2 3 4; do
    echo "-- client $i --"
    cat /tmp/b$i.log
done
echo "-- aggregate --"
awk '/rps=/ {
    for (k=1; k<=NF; k++) if ($k ~ /^rps=/) { sub(/rps=/, "", $k); rps += $k+0 }
    for (k=1; k<=NF; k++) if ($k ~ /^reqs=/) { sub(/reqs=/, "", $k); reqs += $k+0 }
} END { printf "aggregate rps=%d reqs=%d\n", rps, reqs }' /tmp/b*.log
kill -9 $SVR 2>/dev/null
sleep 0.3
echo "done"
