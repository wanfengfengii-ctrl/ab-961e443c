#!/usr/bin/env python3
"""API smoke tests for the SBOM license evaluation service.

Covers the compliant scenario, the denied scenario, verdict determinism
under input reordering, and per-field validation errors.  Exits non-zero
if any check fails.

Usage: python3 scripts/smoke.py [base-url]
"""

import copy
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE_URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.environ.get("APP_URL", "http://127.0.0.1:8000")
).rstrip("/")

PASSES = []
FAILURES = []


def check(name, condition, detail=""):
    if condition:
        PASSES.append(name)
        print("PASS  %s" % name)
    else:
        FAILURES.append(name)
        print("FAIL  %s  %s" % (name, detail))


def request(method, path, body=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(payload)
        except ValueError:
            return exc.code, {}


def wait_for_health(timeout_s=120):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            status, body = request("GET", "/health")
            if status == 200 and body.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

COMPLIANT_PAYLOAD = {
    "root": "pkg:root",
    "components": [
        {"bomRef": "pkg:root", "licenses": [{"expression": "MIT"}]},
        {"bomRef": "pkg:a", "licenses": [{"expression": "MIT OR Apache-2.0"}]},
        {
            "bomRef": "pkg:b",
            "licenses": [{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}],
        },
        {"bomRef": "pkg:c", "licenses": [{"expression": "BSD-3-Clause AND MIT"}]},
        # Reachable only via nothing: must be excluded from the verdict even
        # though its license is denied.
        {"bomRef": "pkg:unreachable", "licenses": [{"expression": "GPL-3.0-only"}]},
    ],
    "dependencies": [
        {"ref": "pkg:root", "dependsOn": ["pkg:a", "pkg:b", "pkg:c"]},
        {"ref": "pkg:a", "dependsOn": ["pkg:b"]},
        {"ref": "pkg:b", "dependsOn": ["pkg:a"]},  # dependency cycle
    ],
    "policy": {
        "allowedLicenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-2.0-only"],
        "deniedLicenses": ["GPL-3.0-only"],
        "allowedExceptions": [
            {"license": "GPL-2.0-only", "exception": "Classpath-exception-2.0"}
        ],
    },
}

EXPECTED_WITNESSES = {
    "pkg:root": "MIT",
    "pkg:a": "Apache-2.0",
    "pkg:b": "GPL-2.0-only WITH Classpath-exception-2.0",
    "pkg:c": "BSD-3-Clause AND MIT",
}

DENIED_PAYLOAD = {
    "root": "root",
    "components": [
        {"bomRef": "root", "licenses": [{"expression": "MIT"}]},
        {"bomRef": "denied-lib", "licenses": [{"expression": "GPL-3.0-only"}]},
        {"bomRef": "unknown-lib", "licenses": [{"expression": "Beerware"}]},
        {
            "bomRef": "exc-lib",
            "licenses": [{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}],
        },
    ],
    "dependencies": [
        {"ref": "root", "dependsOn": ["denied-lib", "unknown-lib", "exc-lib"]}
    ],
    "policy": {
        "allowedLicenses": ["MIT", "GPL-2.0-only"],
        "deniedLicenses": ["GPL-3.0-only"],
        "allowedExceptions": [],
    },
}

EXPECTED_REASON_CODES = {
    "denied-lib": ["LICENSE_DENIED"],
    "exc-lib": ["EXCEPTION_NOT_ALLOWED"],
    "unknown-lib": ["LICENSE_NOT_ALLOWED"],
}


def shuffled(payload):
    """Same semantics, different input ordering."""
    out = copy.deepcopy(payload)
    out["components"] = out["components"][::-1]
    out["dependencies"] = out["dependencies"][::-1]
    for dep in out["dependencies"]:
        dep["dependsOn"] = dep["dependsOn"][::-1]
    out["policy"]["allowedLicenses"] = out["policy"]["allowedLicenses"][::-1]
    out["policy"]["deniedLicenses"] = out["policy"]["deniedLicenses"][::-1]
    out["policy"]["allowedExceptions"] = out["policy"]["allowedExceptions"][::-1]
    return out


def scenario_health():
    status, body = request("GET", "/health")
    check("health: GET /health returns 200 ok", status == 200 and body.get("status") == "ok",
          "got %s %s" % (status, body))


def scenario_compliant():
    status, body = request("POST", "/api/sboms/evaluate", body=COMPLIANT_PAYLOAD)
    check("compliant: HTTP 200", status == 200, "got %s" % status)
    check("compliant: verdict is compliant", body.get("status") == "compliant",
          "got %r" % body.get("status"))
    witnesses = {c["bomRef"]: c.get("witness") for c in body.get("components", [])}
    check("compliant: witnesses for every reachable component",
          witnesses == EXPECTED_WITNESSES, "got %r" % witnesses)
    refs = [c["bomRef"] for c in body.get("components", [])]
    check("compliant: components sorted by bomRef", refs == sorted(refs), "got %r" % refs)
    check("compliant: unreachable component excluded",
          "pkg:unreachable" not in witnesses
          and body.get("summary", {}).get("reachableComponents") == 4,
          "got %r" % body.get("summary"))
    check("compliant: no violations", body.get("violations") == [], "got %r" % body.get("violations"))
    return body


def scenario_determinism(first_body):
    status, body = request("POST", "/api/sboms/evaluate", body=shuffled(COMPLIANT_PAYLOAD))
    check("determinism: reordered input yields identical verdict",
          status == 200 and body == first_body,
          "bodies differ" if body != first_body else "status %s" % status)


def scenario_denied():
    status, body = request("POST", "/api/sboms/evaluate", body=DENIED_PAYLOAD)
    check("denied: HTTP 200", status == 200, "got %s" % status)
    check("denied: verdict is non_compliant", body.get("status") == "non_compliant",
          "got %r" % body.get("status"))
    violations = {v["bomRef"]: [r["code"] for r in v["reasons"]] for v in body.get("violations", [])}
    check("denied: failing components and reasons reported",
          violations == EXPECTED_REASON_CODES, "got %r" % violations)
    check("denied: violations sorted by bomRef",
          [v["bomRef"] for v in body.get("violations", [])] == sorted(EXPECTED_REASON_CODES),
          "got %r" % [v["bomRef"] for v in body.get("violations", [])])
    compliant_refs = {c["bomRef"] for c in body.get("components", [])}
    check("denied: compliant root still listed with witness",
          compliant_refs == {"root"}, "got %r" % compliant_refs)


def scenario_validation():
    cases = [
        ("validation: unknown root reference",
         {"root": "ghost", "components": [], "policy": {}},
         ("root", "MISSING_REFERENCE")),
        ("validation: duplicate bomRef",
         {"root": "a", "components": [{"bomRef": "a"}, {"bomRef": "a"}], "policy": {}},
         ("components[1].bomRef", "DUPLICATE_BOM_REF")),
        ("validation: expression parse error",
         {"root": "a", "components": [{"bomRef": "a", "licenses": [{"expression": "MIT AND ("}]}], "policy": {}},
         ("components[0].licenses[0].expression", "EXPRESSION_PARSE_ERROR")),
        ("validation: invalid exception",
         {"root": "a", "components": [{"bomRef": "a", "licenses": [{"expression": "MIT WITH No-Such-Exception"}]}], "policy": {}},
         ("components[0].licenses[0].expression", "INVALID_EXCEPTION")),
        ("validation: unknown dependency reference",
         {"root": "a", "components": [{"bomRef": "a"}],
          "dependencies": [{"ref": "a", "dependsOn": ["ghost"]}], "policy": {}},
         ("dependencies[0].dependsOn[0]", "MISSING_REFERENCE")),
        ("validation: too many components",
         {"root": "c0", "components": [{"bomRef": "c%d" % i} for i in range(201)], "policy": {}},
         ("components", "TOO_MANY_COMPONENTS")),
    ]
    for name, payload, (field, code) in cases:
        status, body = request("POST", "/api/sboms/evaluate", body=payload)
        found = any(e.get("field") == field and e.get("code") == code for e in body.get("errors", []))
        check(name, status == 400 and body.get("status") == "invalid" and found,
              "got %s %s" % (status, body))

    status, body = request("POST", "/api/sboms/evaluate", raw=b"{broken json")
    check("validation: malformed JSON body",
          status == 400 and body.get("errors", [{}])[0].get("code") == "INVALID_JSON",
          "got %s %s" % (status, body))


def scenario_http_edges():
    status, _ = request("GET", "/api/sboms/evaluate")
    check("http: GET on evaluate is 405", status == 405, "got %s" % status)
    status, _ = request("GET", "/does-not-exist")
    check("http: unknown path is 404", status == 404, "got %s" % status)


def main():
    print("smoke target: %s" % BASE_URL)
    if not wait_for_health():
        check("health: service becomes healthy", False, "timed out waiting for /health")
    else:
        check("health: service becomes healthy", True)
        scenario_health()
        first = scenario_compliant()
        scenario_determinism(first)
        scenario_denied()
        scenario_validation()
        scenario_http_edges()

    print("")
    print("smoke summary: %d passed, %d failed" % (len(PASSES), len(FAILURES)))
    if FAILURES:
        for name in FAILURES:
            print("  FAILED: %s" % name)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
