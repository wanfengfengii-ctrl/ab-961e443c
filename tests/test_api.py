import json
import threading
import unittest
import urllib.error
import urllib.request

from app.server import make_server


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _request(self, method, path, body=None, raw=None):
        data = raw
        if data is None and body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path),
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_health(self):
        status, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_evaluate_compliant(self):
        payload = {
            "root": "app",
            "components": [
                {"bomRef": "app", "licenses": [{"expression": "MIT"}]},
                {"bomRef": "lib", "licenses": [{"expression": "Apache-2.0 OR MIT"}]},
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["lib"]}],
            "policy": {"allowedLicenses": ["MIT", "Apache-2.0"]},
        }
        status, body = self._request("POST", "/api/sboms/evaluate", body=payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual([c["bomRef"] for c in body["components"]], ["app", "lib"])
        self.assertEqual(body["components"][1]["witness"], "Apache-2.0")

    def test_evaluate_non_compliant(self):
        payload = {
            "root": "app",
            "components": [
                {"bomRef": "app", "licenses": [{"expression": "MIT"}]},
                {"bomRef": "lib", "licenses": [{"expression": "GPL-3.0-only"}]},
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["lib"]}],
            "policy": {
                "allowedLicenses": ["MIT"],
                "deniedLicenses": ["GPL-3.0-only"],
            },
        }
        status, body = self._request("POST", "/api/sboms/evaluate", body=payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "non_compliant")
        self.assertEqual(body["violations"][0]["bomRef"], "lib")
        self.assertEqual(
            body["violations"][0]["reasons"][0]["code"], "LICENSE_DENIED"
        )

    def test_validation_error_is_400_with_fields(self):
        payload = {
            "root": "ghost",
            "components": [
                {"bomRef": "app", "licenses": [{"expression": "MIT AND ("}]}
            ],
        }
        status, body = self._request("POST", "/api/sboms/evaluate", body=payload)
        self.assertEqual(status, 400)
        self.assertEqual(body["status"], "invalid")
        fields = {(e["field"], e["code"]) for e in body["errors"]}
        self.assertIn(("root", "MISSING_REFERENCE"), fields)
        self.assertIn(
            ("components[0].licenses[0].expression", "EXPRESSION_PARSE_ERROR"), fields
        )

    def test_invalid_json_body(self):
        status, body = self._request(
            "POST", "/api/sboms/evaluate", raw=b"{not json"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["errors"][0]["code"], "INVALID_JSON")

    def test_unknown_path_is_404(self):
        status, _ = self._request("GET", "/nope")
        self.assertEqual(status, 404)

    def test_get_on_evaluate_is_405(self):
        status, _ = self._request("GET", "/api/sboms/evaluate")
        self.assertEqual(status, 405)


if __name__ == "__main__":
    unittest.main()
