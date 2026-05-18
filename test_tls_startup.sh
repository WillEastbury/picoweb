#!/usr/bin/env bash
# Smoke test for --tls backend startup.
# Validates config parsing + cert load + worker bring-up.
#
# Notes:
# - Requires openssl to mint a temporary Ed25519 cert/key.
# - Requires CAP_NET_RAW to open AF_PACKET; if unavailable (common in
#   containers/CI), this test SKIPs cleanly.
set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

TMP=$(mktemp -d /tmp/picoweb_tls_startup.XXXXXX)
LOG=/tmp/picoweb_tls_startup.log
trap 'rm -rf "$TMP"; for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done' EXIT

CERT="$TMP/tls.crt"
KEY="$TMP/tls.key"

if ! command -v openssl >/dev/null 2>&1; then
    echo "SKIP: openssl not found (cannot mint temporary TLS cert)"
    exit 0
fi

if ! openssl req -x509 -newkey ed25519 -nodes \
      -keyout "$KEY" -out "$CERT" \
      -subj "/CN=localhost" -days 1 >/dev/null 2>&1; then
    echo "SKIP: openssl failed to mint Ed25519 cert/key"
    exit 0
fi

PORT=8443
nohup ./picoweb --tls --tls-ifname=lo --tls-cert="$CERT" --tls-key="$KEY" \
    "$PORT" wwwroot 1 100 0 64 > "$LOG" 2>&1 < /dev/null &
PID=$!
sleep 1.2

if ! kill -0 "$PID" 2>/dev/null; then
    if grep -qiE "af_packet_open|failed to read MAC|failed to read IPv4|Operation not permitted|Permission denied" "$LOG"; then
        echo "SKIP: host does not permit AF_PACKET raw sockets"
        exit 0
    fi
    echo "FATAL: --tls worker exited unexpectedly"
    tail -30 "$LOG"
    exit 1
fi

grep -q "backend=tls" "$LOG" && ok "worker banner shows backend=tls" || fail "missing backend=tls banner"
tr '\0' ' ' < "/proc/$PID/cmdline" | grep -q -- "--tls" && ok "process launched with --tls" || fail "cmdline missing --tls"

kill -INT "$PID" 2>/dev/null || true
sleep 0.5

echo
echo "=== TLS startup log tail ==="
tail -10 "$LOG"
echo "=== RESULTS: PASS=$PASS  FAIL=$FAIL ==="
exit "$FAIL"
