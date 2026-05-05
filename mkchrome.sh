#!/usr/bin/env bash
# Quick helper to (re)create the _chrome/ demo for the localhost vhost.
# Run from anywhere; resolves wwwroot/ relative to this script.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=wwwroot/localhost/_chrome
mkdir -p "$ROOT"
cat > "$ROOT/header.html" <<'HDR'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>chromed</title></head>
<body><header><nav>[CHROME-HEADER nav]</nav></header><main>
HDR
cat > "$ROOT/footer.html" <<'FTR'
</main><footer>[CHROME-FOOTER picoweb]</footer></body></html>
FTR
ls -la "$ROOT"
echo "--- header ---"
cat "$ROOT/header.html"
echo "--- footer ---"
cat "$ROOT/footer.html"
