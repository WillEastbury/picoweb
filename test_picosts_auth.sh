#!/usr/bin/env bash
# test_picosts_auth.sh — verifies PicoSTS (external OIDC authority) login
# integration end-to-end against a minimal fake PicoSTS /userinfo endpoint:
#   - userinfo success + JWT payload iss/aud/exp/nbf/sub checks (all must
#     pass for login to succeed; each is individually tested as a negative
#     case too)
#   - the issued pw_session cookie is the stateless "v1." HMAC-signed form
#     (not the node-local session table used by google/entra)
#   - Path=/ on the cookie: a session established via /wal/auth/login also
#     authorizes /site/ (static_pack) and /ide/card/ (IDE raw card) writes
#   - cluster-safety: a SECOND independent picoweb process (its own
#     in-memory state, no shared session table) sharing the same
#     --picosts-cookie-key accepts the SAME cookie for /wal/auth/me --
#     this is only possible because the cookie is stateless.
#
# We never talk to the real developercli/sts service here (that's a .NET
# project outside this repo's build); we don't need to -- picoweb only
# needs a bearer token whose /userinfo response + JWT payload satisfy its
# validation contract, so a tiny fake server + hand-built (unsigned; this
# module never checks the JWT signature, matching its documented contract
# of userinfo-success + payload iss/aud/exp/nbf/sub checks) JWT is enough.

set -u
cd "$(dirname "$0")"

STS_PORT=9391
PORT_A=9392
PORT_B=9393
NODES="127.0.0.1:$PORT_A,127.0.0.1:$PORT_B"
COOKIE_KEY="test-cluster-shared-secret"
ISSUER="http://127.0.0.1:$STS_PORT"

DIR_A="$(mktemp -d /tmp/pw-sts-a.XXXXXX)"
DIR_B="$(mktemp -d /tmp/pw-sts-b.XXXXXX)"
WWW="$(mktemp -d)"
mkdir -p "$WWW/localhost"; echo ok > "$WWW/localhost/index.html"

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$DIR_A" "$DIR_B" "$WWW"
}
trap cleanup EXIT

PASS=0
FAIL=0
check() {
    local desc="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        echo "ok   $desc -> $got"
        PASS=$((PASS+1))
    else
        echo "FAIL $desc -> got '$got' want '$want'"
        FAIL=$((FAIL+1))
    fi
}
check_prefix() {
    local desc="$1" got="$2" want_prefix="$3"
    if [[ "$got" == "$want_prefix"* ]]; then
        echo "ok   $desc -> matches prefix '$want_prefix'"
        PASS=$((PASS+1))
    else
        echo "FAIL $desc -> got '$got', wanted prefix '$want_prefix'"
        FAIL=$((FAIL+1))
    fi
}
contains() {
    local desc="$1" haystack="$2" needle="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "ok   $desc"
        PASS=$((PASS+1))
    else
        echo "FAIL $desc -> '$haystack' does not contain '$needle'"
        FAIL=$((FAIL+1))
    fi
}
not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "ok   $desc"
        PASS=$((PASS+1))
    else
        echo "FAIL $desc -> '$haystack' unexpectedly contains '$needle'"
        FAIL=$((FAIL+1))
    fi
}

# ---- fake PicoSTS: only GET /userinfo, bearer-gated ----
FAKE_STS_PY="$(mktemp /tmp/pw-fake-sts.XXXXXX.py)"
cat > "$FAKE_STS_PY" <<'PYEOF'
import http.server, json, sys

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/userinfo":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self.send_response(401); self.end_headers(); return
            token = auth[len("Bearer "):]
            # The fake token payload's "sub" is echoed straight back as the
            # userinfo sub, EXCEPT for the special marker token used by the
            # sub-mismatch negative test, which always answers "someone-else".
            if token == "SUB_MISMATCH_MARKER":
                sub = "someone-else"
            else:
                import base64
                parts = token.split(".")
                pad = "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
                sub = payload.get("sub", "unknown")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"sub": sub}).encode())
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF
python3 "$FAKE_STS_PY" "$STS_PORT" &
PIDS+=($!)
sleep 0.3

# ---- JWT-shaped (unsigned; signature is never checked -- see module doc
# comment in src/api.c's oidc_validate_picosts) token builder ----
mk_jwt() {
    python3 - "$@" <<'PYEOF'
import base64, json, sys, time
iss, aud, sub, exp_offset, nbf_offset = sys.argv[1:6]
def b64u(obj):
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
now = int(time.time())
header = {"alg": "none", "typ": "JWT"}
payload = {"iss": iss, "aud": aud, "sub": sub,
           "exp": now + int(exp_offset), "nbf": now + int(nbf_offset)}
print(b64u(header) + "." + b64u(payload) + ".sig")
PYEOF
}

GOOD_TOKEN=$(mk_jwt "$ISSUER" "api" "user-42" 300 -60)
EXPIRED_TOKEN=$(mk_jwt "$ISSUER" "api" "user-42" -60 -120)
NOTYET_TOKEN=$(mk_jwt "$ISSUER" "api" "user-42" 300 120)
WRONG_AUD_TOKEN=$(mk_jwt "$ISSUER" "wrong-aud" "user-42" 300 -60)
WRONG_ISS_TOKEN=$(mk_jwt "http://evil.example" "api" "user-42" 300 -60)
SUB_MISMATCH_TOKEN="SUB_MISMATCH_MARKER"

echo "== node A: picoweb with --picosts-issuer=$ISSUER =="
./picoweb --picowal-device="$DIR_A" --picowal-format \
          --picowal-static-card=1 --picowal-static-prefix=/site/ \
          --ide-prefix=/ide/ \
          --picowal-node-id="127.0.0.1:$PORT_A" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          --oidc-cookie-auth --picosts-issuer="$ISSUER" --picosts-audience=api \
          --picosts-client-id=spa --picosts-cookie-key="$COOKIE_KEY" \
          "$PORT_A" "$WWW" 1 100 0 64 > /tmp/pw-sts-a.log 2>&1 &
PIDS+=($!)
echo "== node B: independent process, SAME --picosts-cookie-key, no shared state =="
./picoweb --picowal-device="$DIR_B" --picowal-format \
          --picowal-static-card=1 --picowal-static-prefix=/site/ \
          --ide-prefix=/ide/ \
          --picowal-node-id="127.0.0.1:$PORT_B" --picowal-partition-nodes="$NODES" \
          --picowal-partition-mode=proxy \
          --oidc-cookie-auth --picosts-issuer="$ISSUER" --picosts-audience=api \
          --picosts-client-id=spa --picosts-cookie-key="$COOKIE_KEY" \
          "$PORT_B" "$WWW" 1 100 0 64 > /tmp/pw-sts-b.log 2>&1 &
PIDS+=($!)
sleep 0.6

login() {
    local port="$1" token="$2"
    curl -sS -D - -o /dev/null --max-time 5 -X POST -H 'X-PW-Auth: 1' -H 'Content-Type: application/json' \
        --data "{\"provider\":\"picosts\",\"access_token\":\"$token\"}" \
        "http://127.0.0.1:$port/wal/auth/login"
}

echo
echo "== negative cases: each must be rejected (401) =="
resp=$(login "$PORT_A" "$EXPIRED_TOKEN")
check "expired token rejected" "$(echo "$resp" | head -1 | tr -d '\r')" "HTTP/1.1 401 Unauthorized"
resp=$(login "$PORT_A" "$NOTYET_TOKEN")
check "not-yet-valid (nbf) token rejected" "$(echo "$resp" | head -1 | tr -d '\r')" "HTTP/1.1 401 Unauthorized"
resp=$(login "$PORT_A" "$WRONG_AUD_TOKEN")
check "wrong audience rejected" "$(echo "$resp" | head -1 | tr -d '\r')" "HTTP/1.1 401 Unauthorized"
resp=$(login "$PORT_A" "$WRONG_ISS_TOKEN")
check "wrong issuer rejected" "$(echo "$resp" | head -1 | tr -d '\r')" "HTTP/1.1 401 Unauthorized"
resp=$(login "$PORT_A" "$SUB_MISMATCH_TOKEN")
check "userinfo/JWT sub mismatch rejected" "$(echo "$resp" | head -1 | tr -d '\r')" "HTTP/1.1 401 Unauthorized"

echo
echo "== valid login on node A =="
resp=$(login "$PORT_A" "$GOOD_TOKEN")
check "valid picosts token accepted" "$(echo "$resp" | head -1 | tr -d '\r')" "HTTP/1.1 204 No Content"
cookie_line=$(echo "$resp" | grep -i '^set-cookie:' | tr -d '\r')
contains "cookie is stateless v1. form" "$cookie_line" "pw_session=v1."
check "cookie Path is / (covers /ide/,/site/,/app/)" "$(echo "$cookie_line" | grep -io 'path=/;' | tr 'A-Z' 'a-z')" "path=/;"
cookie_val=$(echo "$cookie_line" | sed -E 's/^[Ss]et-[Cc]ookie: ?//; s/;.*//')

echo
echo "== /wal/auth/me reflects the signed-in principal (node A) =="
me=$(curl -sS --max-time 5 -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" "http://127.0.0.1:$PORT_A/wal/auth/me")
check "auth/me returns sub" "$me" '{"principal":"user-42"}'

echo
echo "== stateless cookie authorizes /site/ (static_pack) and /ide/card/ writes on node A =="
put_site=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X PUT -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" \
    --data-binary '<h1>via picosts cookie</h1>' "http://127.0.0.1:$PORT_A/site/0/index.html")
check "PUT /site/0/index.html with picosts cookie" "$put_site" "204"
put_card=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X PUT -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" \
    --data-binary 'source via picosts cookie' "http://127.0.0.1:$PORT_A/ide/card/3/1")
check "PUT /ide/card/3/1 with picosts cookie" "$put_card" "204"

echo
echo "== cluster-safety: node B (independent process) accepts node A's cookie =="
me_b=$(curl -sS --max-time 5 -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" "http://127.0.0.1:$PORT_B/wal/auth/me")
check "node B auth/me accepts node A's stateless cookie" "$me_b" '{"principal":"user-42"}'
put_card_b=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X PUT -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" \
    --data-binary 'source via node A cookie, on node B' "http://127.0.0.1:$PORT_B/ide/card/3/1")
check "node B accepts node A's cookie for /ide/card/ write" "$put_card_b" "204"

echo
echo "== cookie-authenticated partition fan-out forwards the session to every shard =="
for path_body in \
    "metadata/name/40|{\"name\":\"authitems\"}" \
    "metadata/schema/40|{\"fields\":\"name\",\"types\":\"name=string\"}"; do
    path="${path_body%%|*}"; payload="${path_body#*|}"
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X PUT \
        -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" --data-binary "$payload" \
        "http://127.0.0.1:$PORT_A/wal/$path")
    check "PUT /wal/$path with picosts cookie" "$code" "204"
done
for rec in 1 2; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X PUT \
        -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" \
        --data-binary "{\"name\":\"item-$rec\"}" "http://127.0.0.1:$PORT_A/wal/40/$rec")
    check "PUT /wal/40/$rec with picosts cookie" "$code" "204"
done
list_out=$(curl -sS --max-time 5 -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" \
    "http://127.0.0.1:$PORT_B/wal/list/40")
contains "list fan-out merged both records" "$list_out" '"count":2'
not_contains "list fan-out authenticated every shard" "$list_out" '"partial":true'
query_out=$(curl -sS --max-time 5 -X POST -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" \
    --data-binary $'S:name\nF:40' "http://127.0.0.1:$PORT_B/wal/query")
contains "query fan-out merged both records" "$query_out" '"count":2'
not_contains "query fan-out authenticated every shard" "$query_out" '"partial":true'
report_out=$(curl -sS --max-time 5 -X POST -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" \
    --data-binary $'S:name\nF:40' "http://127.0.0.1:$PORT_B/wal/report")
contains "report fan-out merged both records" "$report_out" '"count":2'
not_contains "report fan-out authenticated every shard" "$report_out" '"partial":true'

echo
echo "== logout clears the cookie (client-side; stateless tokens have no server-side revoke) =="
logout_resp=$(curl -sS -D - -o /dev/null --max-time 5 -X POST -H 'X-PW-Auth: 1' -H "Cookie: $cookie_val" "http://127.0.0.1:$PORT_A/wal/auth/logout")
check "logout succeeds" "$(echo "$logout_resp" | head -1 | tr -d '\r')" "HTTP/1.1 204 No Content"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "PASS — all $PASS picosts auth checks green"
    exit 0
else
    echo "FAIL — $FAIL of $((PASS+FAIL)) checks failed"
    echo "--- node A log ---"; cat /tmp/pw-sts-a.log
    echo "--- node B log ---"; cat /tmp/pw-sts-b.log
    exit 1
fi
