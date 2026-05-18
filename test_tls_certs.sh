#!/usr/bin/env bash
# test_tls_certs.sh — unit-test the TLS cert path resolver.
# Builds a tiny driver program that links against src/tls_certs.c
# and exercises every resolution branch.
set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

DRV=$(mktemp /tmp/tls_certs_drv.XXXXXX)
TMP=$(mktemp -d /tmp/picoweb_tls_certs.XXXXXX)
trap 'rm -rf "$DRV" "$TMP" /tmp/tls_certs_drv.c' EXIT

cat > /tmp/tls_certs_drv.c <<'EOF'
#include "tls_certs.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char** argv) {
    const char* c = (argc > 1 && argv[1][0]) ? argv[1] : NULL;
    const char* k = (argc > 2 && argv[2][0]) ? argv[2] : NULL;
    char co[4096], ko[4096];
    int rc = picoweb_tls_locate_certs(c, k, co, ko, sizeof(co), NULL);
    if (rc == 0) printf("OK %s | %s\n", co, ko);
    else         printf("FAIL\n");
    return rc == 0 ? 0 : 1;
}
EOF

cc -O2 -Wall -Wextra -std=c11 -Isrc -o "$DRV" /tmp/tls_certs_drv.c src/tls_certs.c \
    || { echo "FATAL: failed to build driver"; exit 1; }

# === TEST 1: nothing anywhere → fail with diagnostic ===
echo "=== TEST 1: no flags, no /certs, no ./certs → FAIL ==="
pushd "$TMP" >/dev/null
out=$("$DRV" 2>/dev/null); rc=$?
popd >/dev/null
[[ $rc -eq 1 && "$out" == FAIL ]] && ok "exit 1 + 'FAIL' on missing certs" || fail "got rc=$rc out='$out'"

# === TEST 2: --tls-cert without --tls-key → both-or-neither error ===
echo "=== TEST 2: --tls-cert alone → error ==="
out=$("$DRV" /etc/hostname "" 2>/dev/null); rc=$?
[[ $rc -eq 1 && "$out" == FAIL ]] && ok "rejected partial CLI config" || fail "got rc=$rc out='$out'"

# === TEST 3: both CLI flags + readable files → use them ===
echo "=== TEST 3: --tls-cert + --tls-key (readable) → use them ==="
TC=$TMP/cli.crt; TK=$TMP/cli.key
echo crt > "$TC"; echo key > "$TK"
out=$("$DRV" "$TC" "$TK" 2>/dev/null); rc=$?
[[ $rc -eq 0 && "$out" == "OK $TC | $TK" ]] && ok "CLI flags wins" || fail "got rc=$rc out='$out'"

# === TEST 4: CLI cert unreadable → error ===
echo "=== TEST 4: CLI cert path bogus → error ==="
out=$("$DRV" "$TMP/does-not-exist.crt" "$TK" 2>/dev/null); rc=$?
[[ $rc -eq 1 && "$out" == FAIL ]] && ok "rejected unreadable CLI cert" || fail "got rc=$rc out='$out'"

# === TEST 5: ./certs/tls.crt + tls.key in cwd → local fallback ===
echo "=== TEST 5: cwd ./certs/tls.{crt,key} → local-dev path ==="
mkdir -p "$TMP/certs"
echo localcrt > "$TMP/certs/tls.crt"
echo localkey > "$TMP/certs/tls.key"
pushd "$TMP" >/dev/null
out=$("$DRV" 2>/dev/null); rc=$?
popd >/dev/null
[[ $rc -eq 0 && "$out" == "OK ./certs/tls.crt | ./certs/tls.key" ]] && \
    ok "fell back to ./certs/tls.{crt,key}" || fail "got rc=$rc out='$out'"

# === TEST 6: ./certs only key → not enough, fail ===
echo "=== TEST 6: ./certs missing tls.crt → fail ==="
rm -f "$TMP/certs/tls.crt"
pushd "$TMP" >/dev/null
out=$("$DRV" 2>/dev/null); rc=$?
popd >/dev/null
[[ $rc -eq 1 && "$out" == FAIL ]] && ok "rejected partial ./certs/" || fail "got rc=$rc out='$out'"

# === TEST 7: /certs k8s path beats ./certs local path ===
# Can only run if /certs/tls.crt + tls.key exist (typically only in
# a real cert-manager pod). On dev hosts this auto-skips.
echo "=== TEST 7: k8s /certs/tls.{crt,key} beats local ./certs (cond) ==="
if [ -r /certs/tls.crt ] && [ -r /certs/tls.key ]; then
    mkdir -p "$TMP/certs"
    echo localcrt > "$TMP/certs/tls.crt"
    echo localkey > "$TMP/certs/tls.key"
    pushd "$TMP" >/dev/null
    out=$("$DRV" 2>/dev/null); rc=$?
    popd >/dev/null
    [[ $rc -eq 0 && "$out" == "OK /certs/tls.crt | /certs/tls.key" ]] && \
        ok "k8s /certs path wins over local ./certs" || fail "got rc=$rc out='$out'"
else
    echo "  SKIP: no /certs/tls.{crt,key} on this host (k8s-only test)"
fi

# === TEST 8: CLI flags beat both filesystem paths ===
echo "=== TEST 8: explicit --tls-cert/--tls-key beats ./certs ==="
mkdir -p "$TMP/certs"
echo localcrt > "$TMP/certs/tls.crt"
echo localkey > "$TMP/certs/tls.key"
TC=$TMP/explicit.crt; TK=$TMP/explicit.key
echo c > "$TC"; echo k > "$TK"
pushd "$TMP" >/dev/null
out=$("$DRV" "$TC" "$TK" 2>/dev/null); rc=$?
popd >/dev/null
[[ $rc -eq 0 && "$out" == "OK $TC | $TK" ]] && \
    ok "CLI flags override local ./certs" || fail "got rc=$rc out='$out'"

echo
echo "=== RESULTS: PASS=$PASS  FAIL=$FAIL ==="
exit "$FAIL"
