#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
sleep 1

run_case() {
    local label="$1"; shift
    local args="$*"
    echo "=== $label (args: $args) ==="
    nohup ./picoweb $args > /tmp/picoweb.log 2>&1 < /dev/null &
    local pid=$!
    sleep 2
    grep -E '(ZEROCOPY|zerocopy|warn:)' /tmp/picoweb.log || true

    echo "-- short response (under threshold) --"
    curl -sS -i -H 'Host: localhost' http://127.0.0.1:8080/health | head -3

    echo "-- larger response (likely over) --"
    curl -sS -o /dev/null -w 'http=%{http_code} size=%{size_download} time=%{time_total}\n' \
        -H 'Host: localhost' http://127.0.0.1:8080/

    echo "-- many requests on a single keep-alive conn (drain test) --"
    seq 1 100 | xargs -I{} echo "/" | head -100 | tr '\n' ' ' >/dev/null
    urls=""
    for i in $(seq 1 100); do urls="$urls http://127.0.0.1:8080/"; done
    curl -sS -o /dev/null -w 'connects=%{num_connects} reused=%{num_reused} time=%{time_total}\n' \
        -H 'Host: localhost' $urls
    echo "-- log tail --"
    tail -5 /tmp/picoweb.log
    kill -INT $pid 2>/dev/null || true
    sleep 1
    for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
    echo
}

run_case "ZC OFF (control)" 8080 wwwroot 2 100 0
run_case "ZC ON, threshold=1024B" 8080 wwwroot 2 100 1024
run_case "ZC ON, threshold=16384B (default recommended)" 8080 wwwroot 2 100 16384

echo "=== Done ==="
