#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
sleep 1

# Create a 256KB resource so ZC actually engages even at 16K threshold.
mkdir -p wwwroot/localhost/big
dd if=/dev/urandom of=wwwroot/localhost/big/blob.bin bs=1024 count=256 status=none

bench() {
    local label="$1"; shift
    echo "=== $label ==="
    nohup ./picoweb $* > /tmp/picoweb.log 2>&1 < /dev/null &
    local pid=$!
    sleep 1.5
    grep -E '(zerocopy|MSG_ZEROCOPY|warn:)' /tmp/picoweb.log

    # Sanity: confirm 256KB body comes back intact
    sz=$(curl -sS -o /dev/null -w '%{size_download}' -H 'Host: localhost' http://127.0.0.1:8080/big/blob.bin)
    echo "size_download=$sz (expected 262144)"

    # Throughput: 5s of 64-conn keep-alive hammering
    if command -v wrk >/dev/null; then
      wrk -t2 -c64 -d5s -H 'Host: localhost' http://127.0.0.1:8080/big/blob.bin 2>&1 | grep -E 'Req|Trans|Rate'
    else
      # crude throughput probe with curl: 200 sequential requests
      start=$(date +%s%N)
      for i in $(seq 1 200); do
        curl -sS -o /dev/null -H 'Host: localhost' http://127.0.0.1:8080/big/blob.bin
      done
      end=$(date +%s%N)
      echo "200 sequential requests: $(( (end - start) / 1000000 )) ms"
    fi

    # No EPOLLERR-induced disconnects?
    echo "log tail:"
    tail -3 /tmp/picoweb.log

    kill -INT $pid 2>/dev/null || true
    sleep 0.5
    for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
    echo
}

bench "ZC OFF" 8080 wwwroot 2 0 0
bench "ZC ON, threshold=16K" 8080 wwwroot 2 0 16384

# Cleanup
rm -rf wwwroot/localhost/big
echo "=== done ==="
