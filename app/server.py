"""SBOM 许可证评估 HTTP 服务（仅用标准库）。

路由：
* GET  /healthz           健康检查
* POST /api/sboms/evaluate 许可证策略裁决
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.evaluation import (
    ValidationFailed,
    evaluate,
    validation_error_body,
)


class _Handler(BaseHTTPRequestHandler):
    server_version = "SbomEval/1.0"

    def _write_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - http.server 约定
        if self.path.split("?", 1)[0] == "/healthz":
            self._write_json(200, {"status": "ok"})
        else:
            self._write_json(404, {"error": {"code": "not_found", "message": "未知路由"}})

    def do_POST(self) -> None:  # noqa: N802 - http.server 约定
        path = self.path.split("?", 1)[0]
        if path != "/api/sboms/evaluate":
            self._write_json(404, {"error": {"code": "not_found", "message": "未知路由"}})
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._write_json(
                400,
                {
                    "error": {
                        "code": "invalid_json",
                        "message": f"请求体不是合法 JSON: {exc}",
                    }
                },
            )
            return

        try:
            body, status = evaluate(payload)
        except ValidationFailed as exc:
            self._write_json(400, validation_error_body(exc.errors))
            return
        self._write_json(status, body)

    def log_message(self, fmt: str, *args) -> None:  # 静默常规访问日志
        return


def create_server(host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), _Handler)


def main() -> None:
    import os

    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "8080"))
    server = create_server(host, port)
    print(f"SBOM 评估服务监听 http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
