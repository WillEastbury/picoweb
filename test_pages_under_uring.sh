#!/usr/bin/env bash
# Run the existing regression suite (test_pages.sh) against the
# io_uring backend. We just inject `--io_uring` into every place
# test_pages.sh launches ./picoweb. Same binary, different flag.
set -uo pipefail
cd "$(dirname "$0")"

for p in $(pgrep -x picoweb 2>/dev/null); do
    kill -9 "$p" 2>/dev/null
done
sleep 0.3

# Patch in /tmp; never mutate test_pages.sh in-tree. Inject an
# absolute cd line so the relative ./picoweb lookups still work
# from /tmp. Insert --io_uring as the first arg to every ./picoweb
# launch.
HERE="$(pwd)"
sed -e 's|^make 2>&1 .*|echo "(skipping make in regression-under-uring run)"|' \
    -e 's|\./picoweb |./picoweb --io_uring |g' \
    -e "s|^cd \"\\\$(dirname.*|cd \"$HERE\"|" \
    test_pages.sh > /tmp/test_pages_uring.sh
chmod +x /tmp/test_pages_uring.sh

timeout 60 bash /tmp/test_pages_uring.sh
rc=$?
rm -f /tmp/test_pages_uring.sh
exit $rc
