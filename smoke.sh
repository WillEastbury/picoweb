#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
pkill -INT -f 'picoweb 8080' 2>/dev/null || true
sleep 0.3
./picoweb 8080 ./wwwroot 2 > /tmp/picoweb.log 2>&1 &
SERVER_PID=$!
sleep 0.5
echo "=== STARTUP ==="
cat /tmp/picoweb.log
echo
echo "=== TESTS (curl) ==="

c() {
    local label="$1"; shift
    echo
    echo "-- $label --"
    curl --silent --show-error --max-time 2 -i "$@" 2>&1 | head -8
}

c "GET / (localhost)"          -H "Host: localhost"        http://127.0.0.1:8080/
c "GET /css/style.css"         -H "Host: localhost"        http://127.0.0.1:8080/css/style.css
c "GET /missing (404)"         -H "Host: localhost"        http://127.0.0.1:8080/missing
c "HEAD / (no body)"     -I    -H "Host: localhost"        http://127.0.0.1:8080/
c "POST / (405)"     -X POST   -H "Host: localhost"        http://127.0.0.1:8080/
c "PUT / (405)"      -X PUT    -H "Host: localhost"        http://127.0.0.1:8080/
c "DELETE / (405)"   -X DELETE -H "Host: localhost"        http://127.0.0.1:8080/
c "vhost _default fallback"    -H "Host: unknown.example"  http://127.0.0.1:8080/
c "path traversal (400)"       -H "Host: localhost"        --path-as-is http://127.0.0.1:8080/../etc/passwd
c "alias /css (no trailing /)" -H "Host: localhost"        http://127.0.0.1:8080/css
c "alias /css/ (with /)"       -H "Host: localhost"        http://127.0.0.1:8080/css/

echo
echo "=== keep-alive (curl 5 reqs / one conn) ==="
curl --silent -o /dev/null -w "code=%{http_code} reused=%{num_connects}\n" \
     -H "Host: localhost" \
     http://127.0.0.1:8080/ http://127.0.0.1:8080/css/style.css \
     http://127.0.0.1:8080/ http://127.0.0.1:8080/missing http://127.0.0.1:8080/

echo
echo "=== shutdown ==="
kill -INT "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null
echo "done"
