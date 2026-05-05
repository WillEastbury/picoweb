#!/usr/bin/env bash
# picocompress (BareMetal.Compress wire-compat) end-to-end test.
set -uo pipefail
cd "$(dirname "$0")"
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
sleep 1

# Make a deliberately compressible body so we can prove the variant is in use.
mkdir -p wwwroot/localhost/zz
python3 -c "
import sys
# 8KB of repetitive English — should compress well
chunk = 'the quick brown fox jumps over the lazy dog. ' * 200
open('wwwroot/localhost/zz/big.txt', 'w').write(chunk)
" 

raw_size=$(wc -c < wwwroot/localhost/zz/big.txt)
echo "raw body size: $raw_size"

nohup ./picoweb 8080 wwwroot 2 100 0 > /tmp/picoweb.log 2>&1 < /dev/null &
pid=$!
sleep 1.5

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# === TEST 1: identity (no Accept-Encoding) returns raw body =====
echo "=== TEST 1: no Accept-Encoding -> identity ==="
out=$(curl -sS -i -H 'Host: localhost' http://127.0.0.1:8080/zz/big.txt)
echo "$out" | head -8
echo "$out" | grep -qi 'Content-Encoding:' && fail "should NOT advertise Content-Encoding" || ok "no Content-Encoding header"
sz=$(curl -sS -o /dev/null -w '%{size_download}' -H 'Host: localhost' http://127.0.0.1:8080/zz/big.txt)
[[ "$sz" == "$raw_size" ]] && ok "identity body size = $sz" || fail "identity body size $sz != $raw_size"

# === TEST 2: Accept-Encoding: picoweb-compress -> compressed ====
echo "=== TEST 2: Accept-Encoding: picoweb-compress -> variant ==="
out=$(curl -sS -i -H 'Host: localhost' -H 'Accept-Encoding: picoweb-compress' http://127.0.0.1:8080/zz/big.txt)
echo "$out" | head -8
echo "$out" | grep -qi 'Content-Encoding: picoweb-compress' && ok "Content-Encoding: picoweb-compress" || fail "missing CE"
echo "$out" | grep -qi 'Vary: Accept-Encoding' && ok "Vary header present" || fail "missing Vary"
csz=$(curl -sS -o /dev/null -H 'Accept-Encoding: picoweb-compress' \
       -w '%{size_download}' -H 'Host: localhost' http://127.0.0.1:8080/zz/big.txt)
[[ "$csz" -lt "$raw_size" ]] && ok "compressed $csz < raw $raw_size" || fail "compressed $csz >= raw $raw_size"

# === TEST 3: legacy alias BareMetal.Compress also works ========
echo "=== TEST 3: Accept-Encoding: BareMetal.Compress -> variant ==="
out=$(curl -sS -i -H 'Host: localhost' -H 'Accept-Encoding: BareMetal.Compress' http://127.0.0.1:8080/zz/big.txt)
echo "$out" | grep -i 'Content-Encoding:' || true
echo "$out" | grep -qi 'Content-Encoding: picoweb-compress' && ok "legacy alias maps to picoweb-compress" || fail "legacy alias did not engage variant"

# === TEST 4: Content-Length matches actual byte count ==========
echo "=== TEST 4: Content-Length matches body byte count ==="
ct_len=$(curl -sS -i -H 'Host: localhost' -H 'Accept-Encoding: picoweb-compress' \
         http://127.0.0.1:8080/zz/big.txt | tr -d '\r' | awk '/^Content-Length:/ {print $2; exit}')
echo "header Content-Length=$ct_len  actual-bytes=$csz"
[[ "$ct_len" == "$csz" ]] && ok "Content-Length matches" || fail "Content-Length $ct_len != actual $csz"

# === TEST 5: roundtrip — server-side decoder must agree ========
echo "=== TEST 5: server decoder roundtrips compressed bytes ==="
curl -sS -H 'Host: localhost' -H 'Accept-Encoding: picoweb-compress' -o /tmp/big.pc \
     http://127.0.0.1:8080/zz/big.txt
# Use the codec self-test compiled below to decode and diff.
cat > /tmp/picoweb_compress_roundtrip.c <<'CEOF'
#include "compress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("in"); return 1; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t* in = malloc(n); fread(in, 1, n, f); fclose(f);
    uint8_t* out = malloc(n * 16 + 64);
    int got = metal_decompress(in, n, out, n * 16 + 64);
    if (got < 0) { fprintf(stderr, "decode FAILED\n"); return 2; }
    fwrite(out, 1, got, stdout);
    return 0;
}
CEOF
(cd src && cc -O2 -I. -o /tmp/pcrt /tmp/picoweb_compress_roundtrip.c compress.c)
/tmp/pcrt /tmp/big.pc > /tmp/big.decoded
if cmp -s /tmp/big.decoded wwwroot/localhost/zz/big.txt; then
    ok "decoded body byte-for-byte matches original"
else
    fail "decoded body differs from original ($(wc -c < /tmp/big.decoded) vs $raw_size)"
    diff <(xxd /tmp/big.decoded | head) <(xxd wwwroot/localhost/zz/big.txt | head) || true
fi

# === TEST 6: chromed HTML — variant covers chrome+body =========
echo "=== TEST 6: chromed HTML compressed end-to-end ==="
curl -sS -H 'Host: localhost' -H 'Accept-Encoding: picoweb-compress' -o /tmp/index.pc \
     http://127.0.0.1:8080/
/tmp/pcrt /tmp/index.pc > /tmp/index.decoded 2>/dev/null
if grep -q 'CHROME-HEADER' /tmp/index.decoded && grep -q 'CHROME-FOOTER' /tmp/index.decoded; then
    ok "chrome+body baked into compressed stream"
else
    fail "chrome bytes missing from decoded compressed payload"
    head -c 400 /tmp/index.decoded; echo
fi

# === TEST 7: binary resource — NO compressed variant ===========
echo "=== TEST 7: binary resource has no Content-Encoding ==="
# Check the existing CSS file (it's text and should compress) and a future
# binary by injecting one:
dd if=/dev/urandom of=wwwroot/localhost/zz/blob.bin bs=1 count=2048 status=none
# Need to restart to pick up the new file
kill -INT $pid 2>/dev/null; sleep 0.5
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
nohup ./picoweb 8080 wwwroot 2 100 0 > /tmp/picoweb.log 2>&1 < /dev/null &
pid=$!
sleep 1.5
out=$(curl -sS -i -H 'Host: localhost' -H 'Accept-Encoding: picoweb-compress' \
       http://127.0.0.1:8080/zz/blob.bin)
if echo "$out" | grep -qi 'Content-Encoding: picoweb-compress'; then
    fail "binary resource should NOT serve compressed (random data won't shrink)"
else
    ok "binary resource served as identity"
fi

# === Cleanup ===
kill -INT $pid 2>/dev/null; sleep 0.5
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
rm -rf wwwroot/localhost/zz
echo
echo "=== RESULTS: PASS=$PASS  FAIL=$FAIL ==="
exit $FAIL
