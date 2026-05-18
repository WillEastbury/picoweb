#!/usr/bin/env bash
# Smoke test for --tls --tls-xdp startup wiring.
# This is a capability probe: it SKIPs when host/kernel permissions
# don't allow AF_XDP, which is expected in many CI/container setups.
set -uo pipefail
cd "$(dirname "$0")"

TMP=$(mktemp -d /tmp/picoweb_tls_xdp.XXXXXX)
LOG=/tmp/picoweb_tls_xdp.log
trap 'rm -rf "$TMP"; for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done' EXIT

CERT="$TMP/tls.crt"
KEY="$TMP/tls.key"
if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP: openssl not found"
  exit 0
fi
if ! openssl req -x509 -newkey ed25519 -nodes -keyout "$KEY" -out "$CERT" -subj "/CN=localhost" -days 1 >/dev/null 2>&1; then
  echo "SKIP: failed generating temp cert"
  exit 0
fi

nohup ./picoweb --tls --tls-xdp --tls-ifname=lo --tls-cert="$CERT" --tls-key="$KEY" 8444 wwwroot 1 100 0 64 >"$LOG" 2>&1 < /dev/null &
PID=$!
sleep 1.2

if ! kill -0 "$PID" 2>/dev/null; then
  if grep -qiE "af_xdp_open|Operation not permitted|Permission denied|Address family not supported|Protocol not supported" "$LOG"; then
    echo "SKIP: host/kernel does not allow AF_XDP here"
    exit 0
  fi
  echo "FAIL: --tls --tls-xdp exited unexpectedly"
  tail -30 "$LOG"
  exit 1
fi

grep -q "io=af_xdp" "$LOG" && echo "PASS: backend reported io=af_xdp" || {
  echo "FAIL: missing io=af_xdp banner"
  tail -20 "$LOG"
  exit 1
}

kill -INT "$PID" 2>/dev/null || true
exit 0

