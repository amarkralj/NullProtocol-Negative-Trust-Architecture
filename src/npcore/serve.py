# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Minimal HTTP service around the embedding API (Python standard library only).

    npcore serve --directory directory.json [--host 127.0.0.1] [--port 8080]

    POST /v1/events                 body: one OCSF JSON object, a JSON array, or JSON Lines
    GET  /v1/subjects/<id>          level, trust and evidence of a person or account ("acct:<id>")
    POST /v1/cases/<id>/review      body: {"confirmed": true|false}
    GET  /v1/caep?max=100           pending CAEP SETs (poll; returned events are removed)
    GET  /v1/ledger/verify          hash-chain integrity
    GET  /v1/health

If the environment variable NPCORE_TOKEN is set, every request needs "Authorization: Bearer <token>".
Bind to localhost or put the service behind a TLS-terminating proxy; it is a reference service, not a
hardened product.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .api import NegativeTrust


def make_handler(nt: NegativeTrust):
    token = os.environ.get("NPCORE_TOKEN")

    class H(BaseHTTPRequestHandler):
        server_version = "npcore"

        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self):
            if token and self.headers.get("Authorization") != f"Bearer {token}":
                self._send(401, {"error": "unauthorized"})
                return False
            return True

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n).decode() if n else ""

        def do_GET(self):
            if not self._auth():
                return
            u = urlparse(self.path)
            parts = [unquote(x) for x in u.path.strip("/").split("/")]
            if parts == ["v1", "health"]:
                return self._send(200, {"ok": True, "version": nt.cfg.name})
            if parts == ["v1", "ledger", "verify"]:
                return self._send(200, nt.verify_ledger())
            if parts == ["v1", "caep"]:
                mx = int(parse_qs(u.query).get("max", ["100"])[0])
                return self._send(200, {"sets": nt.take_caep(mx)})
            if len(parts) == 3 and parts[:2] == ["v1", "subjects"]:
                return self._send(200, nt.status(parts[2]))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._auth():
                return
            parts = [unquote(x) for x in urlparse(self.path).path.strip("/").split("/")]
            try:
                raw = self._body().strip()
                if parts == ["v1", "events"]:
                    if raw.startswith("["):
                        recs = json.loads(raw)
                    elif "\n" in raw:
                        recs = [json.loads(x) for x in raw.splitlines() if x.strip()]
                    else:
                        recs = [json.loads(raw)] if raw else []
                    return self._send(200, {"accepted": len(recs), "outputs": list(nt.process_many(recs))})
                if len(parts) == 4 and parts[:2] == ["v1", "cases"] and parts[3] == "review":
                    body = json.loads(raw or "{}")
                    return self._send(200, nt.review(parts[2], bool(body.get("confirmed")), body.get("reviewer", "reviewer")))
            except (ValueError, KeyError) as exc:
                return self._send(400, {"error": str(exc)})
            self._send(404, {"error": "not found"})

    return H


def serve(directory: str, host: str = "127.0.0.1", port: int = 8080, version: str = "v0.9") -> None:
    nt = NegativeTrust(directory, version=version)
    httpd = ThreadingHTTPServer((host, port), make_handler(nt))
    print(f"npcore listening on http://{host}:{port} ({nt.cfg.name})", flush=True)
    httpd.serve_forever()
