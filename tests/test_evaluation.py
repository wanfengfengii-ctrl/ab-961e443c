"""裁决引擎单元测试（标准库 unittest）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.evaluation import (  # noqa: E402
    MAX_COMPONENTS,
    ValidationFailed,
    evaluate,
    parse_expression,
)


def comp(ref: str, expr: str, name: str | None = None) -> dict:
    c = {"bom_ref": ref, "license_expression": expr}
    if name is not None:
        c["name"] = name
    return c


def dep(ref: str, *deps: str) -> dict:
    return {"ref": ref, "depends_on": list(deps)}


POLICY = {
    "allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
    "denied_licenses": ["GPL-3.0-only", "AGPL-3.0-only"],
    "allowed_exceptions": [
        {"license": "GPL-2.0-only", "exception": "Classpath-exception-2.0"}
    ],
}


def payload(components, deps, root="app", policy=None) -> dict:
    p = {"root_component": root, "components": components, "dependencies": deps}
    p.update(policy or POLICY)
    return p


class ExpressionParserTests(unittest.TestCase):
    def test_precedence_and_binds_tighter_than_or(self):
        from app.evaluation import AndNode, LicenseNode, OrNode

        node = parse_expression("MIT OR Apache-2.0 AND ISC")
        self.assertIsInstance(node, OrNode)
        self.assertEqual(node.items[0], LicenseNode("MIT"))
        self.assertIsInstance(node.items[1], AndNode)

    def test_parentheses_change_grouping(self):
        from app.evaluation import AndNode, OrNode

        node = parse_expression("(MIT OR Apache-2.0) AND ISC")
        self.assertIsInstance(node, AndNode)
        self.assertIsInstance(node.items[0], OrNode)

    def test_with_binding(self):
        from app.evaluation import WithNode

        node = parse_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        self.assertEqual(
            node, WithNode("GPL-2.0-only", "Classpath-exception-2.0")
        )

    def test_bad_expressions(self):
        from app.evaluation import _ExpressionError

        for bad in ["", "MIT AND", "(MIT", "MIT)", "MIT WITH", "AND MIT", "MIT OR )", "MIT @@"]:
            with self.subTest(expr=bad):
                with self.assertRaises(_ExpressionError):
                    parse_expression(bad)


class EvaluationTests(unittest.TestCase):
    def test_simple_compliant_lists_witness(self):
        body, status = evaluate(
            payload([comp("app", "MIT", "App"), comp("lib", "Apache-2.0")],
                    [dep("app", "lib")])
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["compliant"])
        witnesses = {c["bom_ref"]: c["witnesses"] for c in body["evaluated_components"]}
        self.assertEqual(witnesses["app"], ["MIT"])
        self.assertEqual(witnesses["lib"], ["Apache-2.0"])
        self.assertEqual(body["violations"], [])

    def test_denied_has_priority_over_allowed(self):
        p = payload(
            [comp("app", "MIT OR GPL-3.0-only")], [], policy={
                "allowed_licenses": ["MIT", "GPL-3.0-only"],
                "denied_licenses": ["GPL-3.0-only"],
                "allowed_exceptions": [],
            }
        )
        body, _ = evaluate(p)
        self.assertTrue(body["compliant"])  # OR 选择了 MIT 分支
        # 直接使用被拒许可证则无法回避
        body, _ = evaluate(payload([comp("app", "GPL-3.0-only")], []))
        self.assertFalse(body["compliant"])
        self.assertIn("拒绝", body["violations"][0]["reasons"][0])

    def test_and_requires_every_term(self):
        body, _ = evaluate(payload([comp("app", "MIT AND Apache-2.0")], []))
        self.assertTrue(body["compliant"])
        body, _ = evaluate(payload([comp("app", "MIT AND GPL-3.0-only")], []))
        self.assertFalse(body["compliant"])
        reasons = body["violations"][0]["reasons"]
        self.assertEqual(len(reasons), 1)
        self.assertIn("GPL-3.0-only", reasons[0])

    def test_or_needs_one_branch_and_reports_all_when_none(self):
        body, _ = evaluate(payload([comp("app", "MIT OR ISC")], []))
        self.assertTrue(body["compliant"])
        body, _ = evaluate(payload([comp("app", "GPL-3.0-only OR AGPL-3.0-only")], []))
        self.assertFalse(body["compliant"])
        reasons = body["violations"][0]["reasons"]
        self.assertEqual(len(reasons), 2)
        self.assertTrue(all(r.startswith("OR 分支") for r in reasons))

    def test_with_needs_explicit_policy_pair(self):
        body, _ = evaluate(
            payload([comp("app", "GPL-2.0-only WITH Classpath-exception-2.0")], [])
        )
        self.assertTrue(body["compliant"])
        self.assertEqual(
            body["evaluated_components"][0]["witnesses"],
            ["GPL-2.0-only WITH Classpath-exception-2.0"],
        )
        # 同样的许可证搭配未被批准的例外 -> 无法满足政策
        body, _ = evaluate(
            payload([comp("app", "GPL-2.0-only WITH Autoconf-exception-3.0")], [])
        )
        self.assertFalse(body["compliant"])
        self.assertIn("WITH", body["violations"][0]["reasons"][0])

    def test_exception_cannot_exempt_denied_license(self):
        p = payload(
            [comp("app", "GPL-3.0-only WITH Classpath-exception-2.0")], [],
            policy={
                "allowed_licenses": [],
                "denied_licenses": ["GPL-3.0-only"],
                "allowed_exceptions": [
                    {"license": "GPL-3.0-only", "exception": "Classpath-exception-2.0"}
                ],
            }
        )
        body, _ = evaluate(p)
        self.assertFalse(body["compliant"])
        self.assertIn("拒绝", body["violations"][0]["reasons"][0])

    def test_only_reachable_closure_is_judged(self):
        body, _ = evaluate(
            payload(
                [
                    comp("app", "MIT"),
                    comp("used", "ISC"),
                    comp("orphan", "GPL-3.0-only"),  # 不可达，不应影响裁决
                ],
                [dep("app", "used")],
            )
        )
        self.assertTrue(body["compliant"])
        self.assertEqual(
            sorted(c["bom_ref"] for c in body["evaluated_components"]),
            ["app", "used"],
        )

    def test_dependency_cycle_does_not_duplicate(self):
        body, _ = evaluate(
            payload(
                [comp("a", "MIT"), comp("b", "ISC"), comp("c", "Apache-2.0")],
                [dep("a", "b"), dep("b", "c"), dep("c", "a")],
                root="a",
            )
        )
        refs = [c["bom_ref"] for c in body["evaluated_components"]]
        self.assertEqual(sorted(refs), ["a", "b", "c"])
        self.assertEqual(len(refs), len(set(refs)))

    def test_transitive_chain_violation_is_surfaced(self):
        body, _ = evaluate(
            payload(
                [comp("app", "MIT"), comp("mid", "MIT"), comp("deep", "AGPL-3.0-only")],
                [dep("app", "mid"), dep("mid", "deep")],
            )
        )
        self.assertFalse(body["compliant"])
        self.assertEqual(body["violations"][0]["bom_ref"], "deep")


class ValidationTests(unittest.TestCase):
    def assert_field_error(self, p, code: str, path_fragment: str):
        with self.assertRaises(ValidationFailed) as ctx:
            evaluate(p)
        codes_paths = [(e.code, e.field_path) for e in ctx.exception.errors]
        self.assertTrue(
            any(code == c and path_fragment in f for c, f in codes_paths),
            f"未找到 {code}/{path_fragment}，实际: {codes_paths}",
        )
        return ctx.exception.errors

    def test_missing_root_reference(self):
        self.assert_field_error(
            payload([comp("app", "MIT")], [], root="ghost"),
            "unresolved_reference", "root_component",
        )

    def test_missing_dependency_target(self):
        self.assert_field_error(
            payload([comp("app", "MIT")], [dep("app", "ghost")]),
            "unresolved_reference", "depends_on",
        )

    def test_dependency_ref_unknown(self):
        self.assert_field_error(
            payload([comp("app", "MIT")], [dep("ghost", "app")]),
            "unresolved_reference", "dependencies[0].ref",
        )

    def test_invalid_expression_is_field_error(self):
        self.assert_field_error(
            payload([comp("app", "MIT AND (ISC")], []),
            "invalid_expression", "license_expression",
        )

    def test_duplicate_bom_ref(self):
        self.assert_field_error(
            payload([comp("app", "MIT"), comp("app", "ISC")], []),
            "duplicate_bom_ref", "bom_ref",
        )

    def test_too_many_components(self):
        components = [comp(f"c{i}", "MIT") for i in range(MAX_COMPONENTS + 1)]
        self.assert_field_error(
            payload(components, []), "too_many_components", "components",
        )

    def test_malformed_exception_pair(self):
        p = payload([comp("app", "MIT")], [])
        p["allowed_exceptions"] = [{"license": "MIT"}]  # 缺 exception
        self.assert_field_error(p, "invalid_type", "exception")


class DeterminismTests(unittest.TestCase):
    def test_input_order_does_not_change_verdict(self):
        import copy
        import json

        components = [
            comp("app", "MIT OR GPL-3.0-only", "App"),
            comp("b", "Apache-2.0 AND ISC"),
            comp("c", "GPL-3.0-only"),
            comp("d", "MIT"),
        ]
        deps = [dep("app", "b"), dep("app", "d"), dep("b", "c"), dep("c", "app")]
        p1 = payload(components, deps)

        components2 = copy.deepcopy(components)
        components2.reverse()
        deps2 = [dep("app", "d"), dep("c", "app"), dep("b", "c"), dep("app", "b")]
        p2 = payload(components2, deps2)

        b1, _ = evaluate(p1)
        b2, _ = evaluate(p2)
        self.assertEqual(
            json.dumps(b1, sort_keys=True, ensure_ascii=False),
            json.dumps(b2, sort_keys=True, ensure_ascii=False),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
