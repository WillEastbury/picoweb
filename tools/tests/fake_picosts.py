#!/usr/bin/env python3
"""fake_picosts.py -- minimal fake PicoSTS authority for the Playwright
/ide/ acceptance test (tools/tests/ide.spec.js). Implements just enough of
the Authorization Code + PKCE surface (GET /authorize, POST /token,
GET /userinfo) for the real bridge script (tools/ide_server_bridge.js) to
complete a login round trip against picoweb's real /wal/auth/login.

The issued JWT is intentionally unsigned -- src/api.c's
oidc_validate_picosts() only decodes claims (iss/aud/exp/nbf/sub), it never
verifies a signature (see test_picosts_auth.sh's own shell-level fake STS,
which does the same thing).

Usage: fake_picosts.py <port> <audience> <subject>
Prints "READY <port>" on stdout once listening (both to confirm ordering
with the caller and to disambiguate our own vs. an already-bound port).
"""
import base64
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Handler(BaseHTTPRequestHandler):
    def _issuer(self):
        return "http://127.0.0.1:%d" % self.server.server_port

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/authorize":
            qs = parse_qs(u.query)
            redirect_uri = qs.get("redirect_uri", [""])[0]
            state = qs.get("state", [""])[0]
            sep = "&" if "?" in redirect_uri else "?"
            dest = "%s%scode=fake-auth-code&state=%s" % (redirect_uri, sep, state)
            self.send_response(302)
            self.send_header("Location", dest)
            self.end_headers()
            return
        if u.path == "/userinfo":
            auth = self.headers.get("Authorization", "")
            token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
            parts = token.split(".")
            if len(parts) < 2:
                self.send_response(401); self.end_headers(); return
            pad = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            try:
                payload = json.loads(base64.urlsafe_b64decode(pad))
            except Exception:
                self.send_response(401); self.end_headers(); return
            body = json.dumps({"sub": payload.get("sub", "")}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/token":
            length = int(self.headers.get("Content-Length", "0") or "0")
            self.rfile.read(length)  # ignore the body (grant_type/code/verifier)
            now = int(time.time())
            header = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            payload = b64u(json.dumps({
                "iss": self._issuer(),
                "aud": self.server.audience,
                "sub": self.server.subject,
                "exp": now + 300,
                "nbf": now - 60,
            }).encode())
            token = "%s.%s." % (header, payload)
            body = json.dumps({"access_token": token, "token_type": "Bearer"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404); self.end_headers()

    def log_message(self, fmt, *args):
        pass  # keep test output quiet


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    audience = sys.argv[2] if len(sys.argv) > 2 else "api"
    subject = sys.argv[3] if len(sys.argv) > 3 else "playwright-user"
    httpd = HTTPServer(("127.0.0.1", port), Handler)
    httpd.audience = audience
    httpd.subject = subject
    print("READY %d" % httpd.server_port, flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
