#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v openssl >/dev/null 2>&1; then
    echo "SKIP: openssl not found"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not found"
    exit 0
fi

PORT="${PORT:-18443}"
TMP="$(mktemp -d /tmp/picoweb-tls-protocol.XXXXXX)"
LOG="/tmp/picoweb-tls-protocol.log"
PID=""

cleanup() {
    if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT

CERT="$TMP/tls.crt"
KEY="$TMP/tls.key"
WWW="$TMP/www"
mkdir -p "$WWW/localhost"
printf 'ok\n' > "$WWW/localhost/index.html"

if ! openssl req -x509 -newkey ed25519 -nodes \
      -keyout "$KEY" -out "$CERT" \
      -subj "/CN=localhost" -days 1 >/dev/null 2>&1; then
    echo "SKIP: openssl failed to mint Ed25519 cert/key"
    exit 0
fi

PICOWEB_INCOMPLETE_REQUEST_TIMEOUT_MS=600 \
    ./picoweb --tls --tls-cert="$CERT" --tls-key="$KEY" \
    "$PORT" "$WWW" 1 100 0 64 > "$LOG" 2>&1 &
PID=$!
sleep 0.7

if ! kill -0 "$PID" 2>/dev/null; then
    echo "FATAL: --tls worker exited unexpectedly"
    tail -40 "$LOG"
    exit 1
fi

python3 - "$PORT" <<'PY'
import socket
import ssl
import sys
import time

port = int(sys.argv[1])

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def request(payload, timeout=2.0):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.settimeout(timeout)
            tls.sendall(payload)
            chunks = []
            while True:
                try:
                    chunk = tls.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

pipeline = (
    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)
resp = request(pipeline)
if resp.count(b"HTTP/1.1 200") != 2:
    raise SystemExit(f"expected two pipelined 200 responses, got: {resp[:200]!r}")

resp = request(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
if b"HTTP/1.1 505" not in resp:
    raise SystemExit(f"expected unsupported HTTP version 505, got: {resp[:200]!r}")

oversized = (
    b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: " +
    (b"a" * 9000) +
    b"\r\nConnection: close\r\n\r\n"
)
resp = request(oversized)
if b"HTTP/1.1 413" not in resp:
    raise SystemExit(f"expected oversized header 413, got: {resp[:200]!r}")

with socket.create_connection(("127.0.0.1", port), timeout=2.0) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
        tls.settimeout(2.0)
        tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
        time.sleep(1.8)
        try:
            tls.sendall(b"done\r\nConnection: close\r\n\r\n")
            data = tls.recv(1024)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, socket.timeout):
            data = b""
        if data:
            raise SystemExit(f"slow incomplete request unexpectedly survived: {data[:200]!r}")

print("tls protocol hardening ok")
PY
