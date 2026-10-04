"""HTTP API for the SBOM license evaluation service.

Endpoints
---------
* ``GET  /health``              -- liveness/readiness probe.
* ``POST /api/sboms/evaluate``  -- evaluate an SBOM against a license policy.

Standard library only; serves HTTP/1.1 with keep-alive.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .evaluate import evaluate_payload

MAX_BODY_BYTES = 1_000_000
EVALUATE_PATH = "/api/sboms/evaluate"
HEALTH_PATH = "/health"


class Handler(BaseHTTPRequestHandler):
    server_version = "sbom-license-gate/1.0"
    protocol_version = "HTTP/1.1"

    # -- helpers -----------------------------------------------------------

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, code: str, message: str) -> None:
        self._send_json(
            status,
            {"status": "error", "errors": [{"field": "$", "code": code, "message": message}]},
        )

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path == HEALTH_PATH:
            self._send_json(200, {"status": "ok"})
        elif self.path == EVALUATE_PATH:
            self._error(405, "METHOD_NOT_ALLOWED", "use POST %s" % EVALUATE_PATH)
        else:
            self._error(404, "NOT_FOUND", "unknown path %r" % self.path)

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path == HEALTH_PATH:
            self._error(405, "METHOD_NOT_ALLOWED", "use GET %s" % HEALTH_PATH)
            return
        if self.path != EVALUATE_PATH:
            self._error(404, "NOT_FOUND", "unknown path %r" % self.path)
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "INVALID_REQUEST", "invalid Content-Length header")
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._error(413, "PAYLOAD_TOO_LARGE", "request body exceeds %d bytes" % MAX_BODY_BYTES)
            return

        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._error(400, "INVALID_JSON", "request body is not valid JSON")
            return

        status, body = evaluate_payload(payload)
        self._send_json(status, body)

    # -- logging -----------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(
            "%s - %s\n" % (self.log_date_time_string(), fmt % args)
        )


def make_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    server = make_server(port=port)
    print("sbom-license-gate listening on 0.0.0.0:%d" % port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
