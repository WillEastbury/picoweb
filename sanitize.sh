#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
pkill -9 picoweb 2>/dev/null || true
sleep 0.3
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./picoweb 8080 ./wwwroot 2 > /tmp/m.log 2>&1 &
SVR=$!
sleep 0.5
echo "=== Hammering with bench (sanitizer build) ==="
./bench 8080 32 15 / localhost
echo
echo "=== Mixed urls / hosts (small smoke) ==="
for url in / /css/style.css /missing /foo /bar; do
    for h in localhost unknown.example _default; do
        curl -s -o /dev/null -w "host=%{remote_ip}  $h  $url -> %{http_code}\n" \
             -H "Host: $h" "http://127.0.0.1:8080$url"
    done
done
echo
echo "=== Stop server, wait for ASan summary ==="
kill -INT $SVR 2>/dev/null
sleep 0.5
kill -KILL $SVR 2>/dev/null
wait $SVR 2>/dev/null
echo "--- server log tail ---"
tail -30 /tmp/m.log
