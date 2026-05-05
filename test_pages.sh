#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo '=== Build ==='
make 2>&1 | tail -10

echo
echo '=== Set up _pages/ test fixtures ==='
PROOT=wwwroot/localhost/_pages
mkdir -p "$PROOT/blog"
# _pages root index.html — should win over top-level localhost/index.html
cat > "$PROOT/index.html" <<'A'
<h2>HOLE: _pages/index.html (HOMEPAGE)</h2>
<p>This came from _pages and should be wrapped in chrome.</p>
A
# A second page in _pages
cat > "$PROOT/about.html" <<'B'
<h2>HOLE: _pages/about.html</h2>
B
# A nested page in _pages/blog/
cat > "$PROOT/blog/post1.html" <<'C'
<h2>HOLE: _pages/blog/post1.html</h2>
C
ls -la "$PROOT" "$PROOT/blog"

echo
echo '=== Start picoweb ==='
# Don't use pkill -f './picoweb' — it would also match parent shells
# whose argv contains the path /picoweb. Match by exact process name.
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
sleep 1
nohup ./picoweb 8080 wwwroot 2 > /tmp/picoweb.log 2>&1 < /dev/null &
SVR_PID=$!
sleep 2
echo "server pid=$SVR_PID"
head -25 /tmp/picoweb.log
echo '---'
ss -tlnp 2>/dev/null | grep -E ':8080 ' || echo 'no listener!'

echo
echo '=== TEST 1: GET / (Host: localhost) — _pages/index.html should win ==='
curl -sS -i -H 'Host: localhost' http://127.0.0.1:8080/ | head -20

echo
echo '=== TEST 2: GET /about.html — chromed page from _pages/ ==='
curl -sS -H 'Host: localhost' http://127.0.0.1:8080/about.html

echo
echo '=== TEST 3: GET /blog/post1.html — nested chromed page ==='
curl -sS -H 'Host: localhost' http://127.0.0.1:8080/blog/post1.html

echo
echo '=== TEST 4: GET /css/style.css — non-html, served normally, NOT chromed ==='
curl -sS -i -H 'Host: localhost' http://127.0.0.1:8080/css/style.css | head -10

echo
echo '=== TEST 5: GET /index.html for _default host — no _pages, no chrome ==='
curl -sS -i -H 'Host: nosuchhost' http://127.0.0.1:8080/ | head -20

echo
echo '=== TEST 6: HEAD / for localhost — body suppressed but Content-Length advertised ==='
curl -sS -I -H 'Host: localhost' http://127.0.0.1:8080/

echo
echo '=== TEST 7: /health works ==='
curl -sS -i -H 'Host: localhost' http://127.0.0.1:8080/health

echo
echo '=== Quick benchmark to confirm no regression ==='
which wrk >/dev/null && wrk -t2 -c64 -d3s -H 'Host: localhost' http://127.0.0.1:8080/ || echo '(wrk not installed)'

echo
echo '=== Server log tail ==='
tail -20 /tmp/picoweb.log

kill $SVR_PID 2>/dev/null || true
echo
echo '=== Done ==='
