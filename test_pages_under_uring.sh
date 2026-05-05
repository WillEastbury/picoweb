#!/usr/bin/env bash
# Run the existing regression suite (test_pages.sh) against the
# io_uring backend. test_pages.sh hard-codes ./picoweb and runs `make`,
# so we generate a patched copy that uses ./picoweb_uring and skips
# the rebuild step.
set -uo pipefail
cd "$(dirname "$0")"

for p in $(pgrep -x picoweb 2>/dev/null) $(pgrep -x picoweb_uring 2>/dev/null); do
    kill -9 "$p" 2>/dev/null
done
sleep 0.3

# Make sure the io_uring binary exists.
[[ -x ./picoweb_uring ]] || make uring 2>&1 | tail -3

# Patch in /tmp; never mutate test_pages.sh in-tree. Inject an
# absolute cd line so the relative ./picoweb_uring lookups still work
# from /tmp.
HERE="$(pwd)"
sed -e 's|^make 2>&1 .*|echo "(skipping make in regression-under-uring run)"|' \
    -e 's|\./picoweb |./picoweb_uring |g' \
    -e 's|pgrep -x picoweb\b|pgrep -x picoweb_uring|g' \
    -e 's|/tmp/picoweb\.log|/tmp/picoweb_uring.log|g' \
    -e "s|^cd \"\\\$(dirname.*|cd \"$HERE\"|" \
    test_pages.sh > /tmp/test_pages_uring.sh
chmod +x /tmp/test_pages_uring.sh

timeout 60 bash /tmp/test_pages_uring.sh
rc=$?
rm -f /tmp/test_pages_uring.sh
exit $rc
