#!/bin/sh
# One-shot verification: unit tests, build validation, and API smoke tests.
# Aggregates every step into a single exit code and exits.
set -u

cd "$(dirname "$0")/.."
APP_URL="${APP_URL:-http://app:8000}"
FAILED=0

step() {
    echo ""
    echo "=== $* ==="
}

step "unit tests"
if python3 -m unittest discover -s tests -t . -v; then
    echo "unit tests: OK"
else
    echo "unit tests: FAILED"
    FAILED=1
fi

step "build validation"
if python3 -m compileall -q app tests scripts; then
    echo "compileall: OK"
else
    echo "compileall: FAILED"
    FAILED=1
fi
if python3 -c "
from app.evaluate import evaluate_payload
code, body = evaluate_payload({
    'root': 'r',
    'components': [{'bomRef': 'r', 'licenses': [{'expression': 'MIT'}]}],
    'policy': {'allowedLicenses': ['MIT']},
})
assert code == 200 and body['status'] == 'compliant', body
print('in-process evaluation: OK')
"; then
    :
else
    echo "in-process evaluation: FAILED"
    FAILED=1
fi

step "API smoke tests (compliant + denied scenarios)"
if python3 scripts/smoke.py "$APP_URL"; then
    echo "smoke tests: OK"
else
    echo "smoke tests: FAILED"
    FAILED=1
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "VERIFY RESULT: ALL CHECKS PASSED"
else
    echo "VERIFY RESULT: FAILURES DETECTED"
fi
exit "$FAILED"
