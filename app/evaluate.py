"""SBOM license policy evaluation.

Semantics
---------
* Only components reachable from the root component (through dependency
  references) are judged; unreachable components never affect the verdict.
  Dependency cycles are traversed once and cannot duplicate results.
* A component's ``licenses`` array is a disjunction: at least one entry must
  be policy-compliant.  Inside an SPDX expression, ``AND`` requires every
  term to be compliant, ``OR`` requires at least one compliant branch, and
  ``AND`` binds tighter than ``OR``.
* A license term is compliant when it is not denied, is explicitly allowed,
  and -- if it carries a ``WITH`` exception -- the (license, exception) pair
  is explicitly allowed by policy.  Denied entries take priority over
  allowed ones.
* Results are deterministic: components are reported sorted by ``bomRef``
  and the adopted witness is the smallest compliant combination (fewest
  terms, then lexicographic), so input ordering never changes the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .spdx_exceptions import SPDX_EXCEPTIONS
from .spdx_expr import And, License, Or, parse_expression

MAX_COMPONENTS = 200

# Reason codes
LICENSE_DENIED = "LICENSE_DENIED"
LICENSE_NOT_ALLOWED = "LICENSE_NOT_ALLOWED"
EXCEPTION_NOT_ALLOWED = "EXCEPTION_NOT_ALLOWED"
NO_LICENSE = "NO_LICENSE"

# Safety bound for combinatorial expansion of AND-of-OR expressions.
_SOLUTION_CAP = 4096


# ---------------------------------------------------------------------------
# Policy terms
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Term:
    license: str
    exception: Optional[str] = None

    def canonical(self) -> str:
        if self.exception:
            return "%s WITH %s" % (self.license, self.exception)
        return self.license


@dataclass(frozen=True)
class Policy:
    allowed: FrozenSet[str]  # lowercased license ids
    denied: FrozenSet[str]  # lowercased license ids
    exceptions: FrozenSet[Tuple[str, str]]  # (license, exception), lowercased


def _term_reasons(term: Term, policy: Policy) -> List[Tuple[str, str]]:
    """Why ``term`` fails the policy; empty list means compliant."""
    lic = term.license.lower()
    if lic in policy.denied:
        # Denied takes priority: no further reasons are reported.
        return [
            (LICENSE_DENIED, "license '%s' is denied by policy" % term.license)
        ]
    reasons: List[Tuple[str, str]] = []
    if lic not in policy.allowed:
        reasons.append(
            (
                LICENSE_NOT_ALLOWED,
                "license '%s' is not in the allowed license list" % term.license,
            )
        )
    if term.exception is not None and (lic, term.exception.lower()) not in policy.exceptions:
        reasons.append(
            (
                EXCEPTION_NOT_ALLOWED,
                "exception '%s' used with license '%s' is not allowed by policy"
                % (term.exception, term.license),
            )
        )
    return reasons


# ---------------------------------------------------------------------------
# Expression evaluation
# ---------------------------------------------------------------------------


def _solution_key(solution: FrozenSet[Term]) -> Tuple[int, str]:
    return (len(solution), " AND ".join(sorted(t.canonical() for t in solution)))


def _solution_text(solution: FrozenSet[Term]) -> str:
    return _solution_key(solution)[1]


def _product(left: List[FrozenSet[Term]], right: List[FrozenSet[Term]]) -> List[FrozenSet[Term]]:
    out = [a | b for a in left for b in right]
    if len(out) > _SOLUTION_CAP:
        out = sorted(out, key=_solution_key)[:_SOLUTION_CAP]
    return out


def _eval_node(node, policy: Policy) -> Tuple[List[FrozenSet[Term]], List[Tuple[str, str]]]:
    """Return (satisfying license sets, failure reasons) for an AST node."""
    if isinstance(node, License):
        term = Term(node.id, node.exception)
        reasons = _term_reasons(term, policy)
        if reasons:
            return [], reasons
        return [frozenset((term,))], []
    if isinstance(node, And):
        solutions: List[FrozenSet[Term]] = [frozenset()]
        reasons: List[Tuple[str, str]] = []
        for child in node.terms:
            child_solutions, child_reasons = _eval_node(child, policy)
            if child_solutions:
                if solutions:
                    solutions = _product(solutions, child_solutions)
            else:
                solutions = []
                reasons.extend(child_reasons)
        return solutions, ([] if solutions else reasons)
    if isinstance(node, Or):
        solutions = []
        reasons = []
        for child in node.options:
            child_solutions, child_reasons = _eval_node(child, policy)
            solutions.extend(child_solutions)
            reasons.extend(child_reasons)
        if solutions:
            unique = {_solution_key(s): s for s in solutions}
            solutions = sorted(unique.values(), key=_solution_key)[:_SOLUTION_CAP]
            return solutions, []
        return [], reasons
    raise TypeError("unknown AST node: %r" % (node,))


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------


@dataclass
class _Component:
    bom_ref: str
    expressions: List[Tuple[str, object]] = field(default_factory=list)


def _err(errors: list, field_: str, code: str, message: str) -> None:
    errors.append({"field": field_, "code": code, "message": message})


def _parse_components(payload: dict, errors: list) -> Dict[str, _Component]:
    components: Dict[str, _Component] = {}
    if "components" not in payload:
        _err(errors, "components", "REQUIRED", "components is required")
        return components
    raw = payload["components"]
    if not isinstance(raw, list):
        _err(errors, "components", "INVALID_TYPE", "components must be an array")
        return components
    if len(raw) > MAX_COMPONENTS:
        _err(
            errors,
            "components",
            "TOO_MANY_COMPONENTS",
            "at most %d components are allowed, got %d" % (MAX_COMPONENTS, len(raw)),
        )
    for i, item in enumerate(raw):
        path = "components[%d]" % i
        if not isinstance(item, dict):
            _err(errors, path, "INVALID_TYPE", "component must be an object")
            continue
        ref = item.get("bomRef")
        if not isinstance(ref, str) or not ref.strip():
            _err(errors, path + ".bomRef", "INVALID_VALUE", "bomRef must be a non-empty string")
            continue
        if ref in components:
            _err(errors, path + ".bomRef", "DUPLICATE_BOM_REF", "duplicate bomRef '%s'" % ref)
            continue
        component = _Component(bom_ref=ref)
        licenses = item.get("licenses", [])
        if not isinstance(licenses, list):
            _err(errors, path + ".licenses", "INVALID_TYPE", "licenses must be an array")
        else:
            for j, entry in enumerate(licenses):
                lpath = "%s.licenses[%d]" % (path, j)
                if isinstance(entry, dict) and "expression" in entry:
                    expr_text, epath = entry["expression"], lpath + ".expression"
                elif (
                    isinstance(entry, dict)
                    and isinstance(entry.get("license"), dict)
                    and "id" in entry["license"]
                ):
                    expr_text, epath = entry["license"]["id"], lpath + ".license.id"
                elif isinstance(entry, str):
                    expr_text, epath = entry, lpath
                else:
                    _err(
                        errors,
                        lpath,
                        "INVALID_VALUE",
                        "license entry must be an object with an 'expression' string",
                    )
                    continue
                if not isinstance(expr_text, str) or not expr_text.strip():
                    _err(errors, epath, "INVALID_VALUE", "expression must be a non-empty string")
                    continue
                ast, parse_err = parse_expression(expr_text)
                if parse_err is not None:
                    _err(errors, epath, parse_err.code, parse_err.message)
                else:
                    component.expressions.append((expr_text, ast))
        components[ref] = component
    return components


def _parse_dependencies(payload: dict, components: Dict[str, _Component], errors: list) -> Dict[str, Set[str]]:
    dep_map: Dict[str, Set[str]] = {}
    raw = payload.get("dependencies", [])
    if raw is None:
        return dep_map
    if not isinstance(raw, list):
        _err(errors, "dependencies", "INVALID_TYPE", "dependencies must be an array")
        return dep_map
    for i, item in enumerate(raw):
        path = "dependencies[%d]" % i
        if not isinstance(item, dict):
            _err(errors, path, "INVALID_TYPE", "dependency entry must be an object")
            continue
        ref = item.get("ref")
        ref_ok = True
        if not isinstance(ref, str) or not ref.strip():
            _err(errors, path + ".ref", "INVALID_VALUE", "ref must be a non-empty string")
            ref_ok = False
        elif ref not in components:
            _err(errors, path + ".ref", "MISSING_REFERENCE", "unknown bomRef '%s'" % ref)
            ref_ok = False
        depends_on = item.get("dependsOn", [])
        if not isinstance(depends_on, list):
            _err(errors, path + ".dependsOn", "INVALID_TYPE", "dependsOn must be an array")
            continue
        for j, child in enumerate(depends_on):
            cpath = "%s.dependsOn[%d]" % (path, j)
            if not isinstance(child, str) or not child.strip():
                _err(errors, cpath, "INVALID_VALUE", "dependsOn entries must be non-empty strings")
                continue
            if child not in components:
                _err(errors, cpath, "MISSING_REFERENCE", "unknown bomRef '%s'" % child)
                continue
            if ref_ok:
                dep_map.setdefault(ref, set()).add(child)
    return dep_map


def _string_set(raw, field_: str, errors: list) -> Set[str]:
    values: Set[str] = set()
    if not isinstance(raw, list):
        _err(errors, field_, "INVALID_TYPE", "%s must be an array" % field_)
        return values
    for i, value in enumerate(raw):
        if not isinstance(value, str) or not value.strip():
            _err(errors, "%s[%d]" % (field_, i), "INVALID_VALUE", "entries must be non-empty strings")
            continue
        values.add(value.lower())
    return values


def _parse_policy(payload: dict, errors: list) -> Policy:
    raw = payload.get("policy")
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        _err(errors, "policy", "INVALID_TYPE", "policy must be an object")
        raw = {}
    allowed = _string_set(raw.get("allowedLicenses", []), "policy.allowedLicenses", errors)
    denied = _string_set(raw.get("deniedLicenses", []), "policy.deniedLicenses", errors)
    exceptions: Set[Tuple[str, str]] = set()
    raw_exceptions = raw.get("allowedExceptions", [])
    if not isinstance(raw_exceptions, list):
        _err(errors, "policy.allowedExceptions", "INVALID_TYPE", "allowedExceptions must be an array")
    else:
        for i, pair in enumerate(raw_exceptions):
            path = "policy.allowedExceptions[%d]" % i
            if not isinstance(pair, dict):
                _err(errors, path, "INVALID_TYPE", "exception allowance must be an object")
                continue
            lic, exc, ok = pair.get("license"), pair.get("exception"), True
            if not isinstance(lic, str) or not lic.strip():
                _err(errors, path + ".license", "INVALID_VALUE", "license must be a non-empty string")
                ok = False
            if not isinstance(exc, str) or not exc.strip():
                _err(errors, path + ".exception", "INVALID_VALUE", "exception must be a non-empty string")
                ok = False
            elif exc.lower() not in SPDX_EXCEPTIONS:
                _err(errors, path + ".exception", "INVALID_EXCEPTION", "unknown exception '%s'" % exc)
                ok = False
            if ok:
                exceptions.add((lic.lower(), exc.lower()))
    return Policy(allowed=frozenset(allowed), denied=frozenset(denied), exceptions=frozenset(exceptions))


# ---------------------------------------------------------------------------
# Component evaluation
# ---------------------------------------------------------------------------


def _eval_component(component: _Component, policy: Policy):
    """Return ``(witness, None)`` when compliant, else ``(None, reasons)``."""
    if not component.expressions:
        return None, [(NO_LICENSE, "component declares no license expression")]
    solutions: List[FrozenSet[Term]] = []
    reasons: List[Tuple[str, str]] = []
    for _text, ast in component.expressions:
        expr_solutions, expr_reasons = _eval_node(ast, policy)
        solutions.extend(expr_solutions)
        reasons.extend(expr_reasons)
    if solutions:
        best = min(solutions, key=_solution_key)
        return _solution_text(best), None
    unique = sorted(set(reasons))
    return None, unique


def _reachable_closure(root: str, dep_map: Dict[str, Set[str]]) -> Set[str]:
    reachable: Set[str] = set()
    stack = [root]
    while stack:
        ref = stack.pop()
        if ref in reachable:
            continue
        reachable.add(ref)
        stack.extend(sorted(dep_map.get(ref, ())))
    return reachable


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def evaluate_payload(payload):
    """Validate and evaluate an evaluation request.

    Returns ``(http_status, body)``.  Validation problems yield ``400`` with
    per-field errors; a successful evaluation yields ``200`` with a
    ``compliant`` or ``non_compliant`` verdict.
    """
    if not isinstance(payload, dict):
        return 400, {
            "status": "invalid",
            "errors": [
                {"field": "$", "code": "INVALID_TYPE", "message": "request body must be a JSON object"}
            ],
        }

    errors: list = []

    root = payload.get("root")
    if "root" not in payload:
        _err(errors, "root", "REQUIRED", "root is required")
        root = None
    elif not isinstance(root, str) or not root.strip():
        _err(errors, "root", "INVALID_VALUE", "root must be a non-empty bomRef string")
        root = None

    components = _parse_components(payload, errors)
    if root is not None and root not in components:
        _err(errors, "root", "MISSING_REFERENCE", "root references unknown bomRef '%s'" % root)

    dep_map = _parse_dependencies(payload, components, errors)
    policy = _parse_policy(payload, errors)

    if errors:
        errors.sort(key=lambda e: (e["field"], e["code"], e["message"]))
        return 400, {"status": "invalid", "errors": errors}

    reachable = _reachable_closure(root, dep_map)

    compliant_components = []
    violations = []
    for ref in sorted(reachable):
        component = components[ref]
        witness, reasons = _eval_component(component, policy)
        expressions = sorted(text for text, _ in component.expressions)
        if witness is not None:
            compliant_components.append(
                {"bomRef": ref, "witness": witness, "expressions": expressions}
            )
        else:
            violations.append(
                {
                    "bomRef": ref,
                    "expressions": expressions,
                    "reasons": [{"code": code, "message": message} for code, message in reasons],
                }
            )

    status = "compliant" if not violations else "non_compliant"
    body = {
        "status": status,
        "root": root,
        "summary": {
            "reachableComponents": len(reachable),
            "compliantComponents": len(compliant_components),
            "violations": len(violations),
        },
        "components": compliant_components,
        "violations": violations,
    }
    return 200, body
