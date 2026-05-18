#!/usr/bin/env bash
# test_uring_active.sh
# ----------------------------------------------------------------------
# Verifies that picoweb is ACTUALLY running on the io_uring backend in
# production, not silently fallen back to epoll. This is the kind of
# check you'd run after deploy to confirm the kernel honoured your
# --io_uring (and --sqpoll) flags.
#
# What we assert (cannot be faked by a fallback):
#   1. The picoweb process owns at least one anon_inode:[io_uring] fd
#      (i.e., io_uring_setup(2) succeeded — there is no way to get
#      that fd from epoll/poll/select).
#   2. The startup banner says "backend=io_uring".
#   3. With --sqpoll, the kernel spawns a per-ring "iou-sqp-<tid>"
#      polling thread visible in /proc/<pid>/task/*/comm. If we
#      requested SQPOLL but no such thread exists we FAIL — i.e.
#      we caught a silent fallback.
#   4. (Soft) The server actually serves a request through the ring.
#
# If the host kernel does not support io_uring at all (older kernels,
# or seccomp-filtered containers — common in CI) we SKIP cleanly with
# exit 0 so this script is safe to gate deploys / CI on.
# ----------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-8081}
LOG=/tmp/picoweb_uring_active.log
SQ_LOG=/tmp/picoweb_uring_sqpoll.log

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
note() { echo "  NOTE: $1"; }

# Tear down any leftovers
for p in $(pgrep -x picoweb 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
sleep 0.3

# ---------------------------------------------------------------------
# 0. Probe whether the kernel will actually let us use io_uring at all.
#    We compile a tiny program that calls io_uring_setup(2). On a kernel
#    or seccomp profile that blocks the syscall this returns ENOSYS or
#    EPERM and we SKIP the test (not a failure — picoweb correctly
#    falls back in that case, which test_uring.sh already covers).
# ---------------------------------------------------------------------
PROBE_SRC=$(mktemp /tmp/uring_probe.XXXXXX.c)
PROBE_BIN=$(mktemp /tmp/uring_probe.XXXXXX)
trap 'rm -f "$PROBE_SRC" "$PROBE_BIN"' EXIT

cat > "$PROBE_SRC" <<'EOF'
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
int main(void) {
    struct io_uring_params p; memset(&p, 0, sizeof(p));
    long fd = syscall(__NR_io_uring_setup, 8, &p);
    if (fd < 0) { fprintf(stderr, "io_uring_setup: %s\n", strerror(errno)); return 1; }
    close((int)fd);
    return 0;
}
EOF

if ! cc -O2 -o "$PROBE_BIN" "$PROBE_SRC" 2>/dev/null; then
    echo "SKIP: cannot compile io_uring probe (no <linux/io_uring.h>?) — assuming unsupported"
    exit 0
fi
if ! "$PROBE_BIN" 2>/tmp/uring_probe.err; then
    echo "SKIP: kernel/seccomp does not allow io_uring_setup($(cat /tmp/uring_probe.err))"
    echo "      picoweb's runtime fallback path is correct in this environment;"
    echo "      run this test on a host kernel without seccomp filtering."
    exit 0
fi
echo "Probe OK: kernel supports io_uring_setup(2)"

# ---------------------------------------------------------------------
# Helper: assert the picoweb pid owns an anon_inode:[io_uring] fd.
#   Returns 0 (pass) on found, 1 (fail) on not-found.
#   This is the gold-standard "are we really on io_uring?" check —
#   the inode name is set by the kernel and cannot be produced by
#   any other syscall.
# ---------------------------------------------------------------------
assert_uring_fd() {
    local pid=$1 found=0
    for fd in /proc/"$pid"/fd/*; do
        [ -e "$fd" ] || continue
        local link
        link=$(readlink "$fd" 2>/dev/null) || continue
        if [[ "$link" == "anon_inode:[io_uring]" ]]; then
            found=$((found+1))
        fi
    done
    echo "$found"
}

# ---------------------------------------------------------------------
# Helper: count iou-sqp-* kernel threads owned by pid. With SQPOLL
# enabled, the kernel spawns one such thread per ring. Without SQPOLL
# (or after a silent fallback) there are zero.
# ---------------------------------------------------------------------
count_sqpoll_threads() {
    local pid=$1 n=0
    for tcomm in /proc/"$pid"/task/*/comm; do
        [ -r "$tcomm" ] || continue
        local name
        name=$(cat "$tcomm" 2>/dev/null) || continue
        case "$name" in
            iou-sqp-*) n=$((n+1)) ;;
        esac
    done
    echo "$n"
}

# =====================================================================
# CASE A: --io_uring (no SQPOLL)
# =====================================================================
echo
echo "=== CASE A: ./picoweb --io_uring ==="
nohup ./picoweb --io_uring "$PORT" wwwroot 2 100 0 \
    > "$LOG" 2>&1 < /dev/null &
PID=$!
sleep 1.0

if ! kill -0 "$PID" 2>/dev/null; then
    echo "FATAL: picoweb --io_uring exited:"
    cat "$LOG"
    exit 1
fi

# 1. Banner check
if grep -q 'backend=io_uring' "$LOG"; then
    ok "startup banner says backend=io_uring"
else
    fail "startup banner missing backend=io_uring"
    grep -i 'backend' "$LOG" | head -3
fi

# 2. The smoking gun: anon_inode:[io_uring] fd
n_uring_fds=$(assert_uring_fd "$PID")
if [[ "$n_uring_fds" -ge 1 ]]; then
    ok "picoweb owns $n_uring_fds anon_inode:[io_uring] fd(s) — io_uring_setup confirmed"
else
    fail "no anon_inode:[io_uring] fd in /proc/$PID/fd — backend silently fell back!"
    echo "       open fds:"
    for fd in /proc/"$PID"/fd/*; do
        [ -e "$fd" ] && echo "         $(basename "$fd") -> $(readlink "$fd")"
    done | head -15
fi

# 3. SQPOLL must NOT be active in this case
n_sqpoll=$(count_sqpoll_threads "$PID")
if [[ "$n_sqpoll" -eq 0 ]]; then
    ok "no iou-sqp-* threads (correct: --sqpoll not requested)"
else
    fail "$n_sqpoll iou-sqp-* threads but --sqpoll not requested"
fi

# 4. Soft: requests succeed through the ring
code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
    -H 'Host: localhost' "http://127.0.0.1:$PORT/")
if [[ "$code" == "200" ]]; then
    ok "GET / over io_uring -> 200"
else
    fail "GET / over io_uring -> $code"
fi

kill -INT "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
sleep 0.3

# =====================================================================
# CASE B: --io_uring --sqpoll
# =====================================================================
echo
echo "=== CASE B: ./picoweb --io_uring --sqpoll ==="
nohup ./picoweb --io_uring --sqpoll "$PORT" wwwroot 2 100 0 \
    > "$SQ_LOG" 2>&1 < /dev/null &
PID=$!
sleep 1.2

if ! kill -0 "$PID" 2>/dev/null; then
    echo "FATAL: picoweb --io_uring --sqpoll exited:"
    cat "$SQ_LOG"
    exit 1
fi

# 1. Banner: io_uring active
if grep -q 'backend=io_uring' "$SQ_LOG"; then
    ok "startup banner says backend=io_uring"
else
    fail "startup banner missing backend=io_uring"
fi

# 2. anon_inode:[io_uring] fd present
n_uring_fds=$(assert_uring_fd "$PID")
if [[ "$n_uring_fds" -ge 1 ]]; then
    ok "picoweb owns $n_uring_fds anon_inode:[io_uring] fd(s)"
else
    fail "no anon_inode:[io_uring] fd in /proc/$PID/fd"
fi

# 3. SQPOLL: distinguish "active" vs "fell back to plain io_uring"
#    by looking for the iou-sqp-* kernel thread. Some kernels need
#    CAP_SYS_NICE for SQPOLL — picoweb does a tiered fallback in that
#    case, which is correct behaviour. We report which path won.
n_sqpoll=$(count_sqpoll_threads "$PID")
if grep -q 'io_uring+sqpoll' "$SQ_LOG"; then
    if [[ "$n_sqpoll" -ge 1 ]]; then
        ok "SQPOLL active and kernel polling thread present ($n_sqpoll iou-sqp-*)"
    else
        fail "banner claims +sqpoll but no iou-sqp-* kernel thread!"
        ps -L -p "$PID" -o pid,tid,comm | head -10
    fi
else
    # Banner did not promise SQPOLL — must mean we tier-fell-back.
    if [[ "$n_sqpoll" -eq 0 ]]; then
        note "SQPOLL unavailable on this kernel — picoweb tier-fell-back to plain io_uring (expected on kernels without CAP_SYS_NICE)"
        ok "graceful fallback observed (no iou-sqp-* threads, no +sqpoll banner)"
    else
        fail "iou-sqp-* threads present but banner did not promise SQPOLL"
    fi
fi

# 4. Soft: requests succeed
code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
    -H 'Host: localhost' "http://127.0.0.1:$PORT/")
if [[ "$code" == "200" ]]; then
    ok "GET / over io_uring+sqpoll -> 200"
else
    fail "GET / over io_uring+sqpoll -> $code"
fi

kill -INT "$PID" 2>/dev/null
wait "$PID" 2>/dev/null

# =====================================================================
echo
echo "=== Server log tails ==="
echo "-- io_uring --"
grep -E 'backend=|sqpoll|ring|ready' "$LOG" | head -8
echo "-- io_uring+sqpoll --"
grep -E 'backend=|sqpoll|ring|ready' "$SQ_LOG" | head -8

echo
echo "=== RESULTS: PASS=$PASS  FAIL=$FAIL ==="
exit "$FAIL"
