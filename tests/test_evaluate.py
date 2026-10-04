import copy
import random
import unittest

from app.evaluate import evaluate_payload


def component(ref, *expressions):
    return {"bomRef": ref, "licenses": [{"expression": e} for e in expressions]}


def base_payload(**overrides):
    payload = {
        "root": "root",
        "components": [component("root", "MIT")],
        "dependencies": [],
        "policy": {
            "allowedLicenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-2.0-only"],
            "deniedLicenses": ["GPL-3.0-only"],
            "allowedExceptions": [
                {"license": "GPL-2.0-only", "exception": "Classpath-exception-2.0"}
            ],
        },
    }
    payload.update(overrides)
    return payload


def evaluate(payload):
    return evaluate_payload(payload)


class VerdictTests(unittest.TestCase):
    def test_single_compliant_component(self):
        status, body = evaluate(base_payload())
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual(
            body["components"],
            [{"bomRef": "root", "witness": "MIT", "expressions": ["MIT"]}],
        )
        self.assertEqual(body["violations"], [])
        self.assertEqual(body["summary"]["reachableComponents"], 1)

    def test_or_needs_one_compliant_branch(self):
        payload = base_payload(
            components=[component("root", "GPL-3.0-only OR MIT")],
        )
        status, body = evaluate(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual(body["components"][0]["witness"], "MIT")

    def test_and_needs_all_terms(self):
        payload = base_payload(
            components=[component("root", "MIT AND GPL-3.0-only")],
        )
        status, body = evaluate(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "non_compliant")
        codes = [r["code"] for r in body["violations"][0]["reasons"]]
        self.assertEqual(codes, ["LICENSE_DENIED"])

    def test_denied_takes_priority_over_allowed(self):
        payload = base_payload()
        payload["policy"]["allowedLicenses"] = ["MIT", "GPL-3.0-only"]
        payload["components"] = [component("root", "GPL-3.0-only")]
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "non_compliant")
        reasons = body["violations"][0]["reasons"]
        self.assertEqual([r["code"] for r in reasons], ["LICENSE_DENIED"])

    def test_denied_branch_in_or_is_pruned_not_fatal(self):
        payload = base_payload(
            components=[component("root", "GPL-3.0-only OR Apache-2.0")],
        )
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual(body["components"][0]["witness"], "Apache-2.0")

    def test_license_not_in_allowed_list(self):
        payload = base_payload(components=[component("root", "Beerware")])
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "non_compliant")
        reasons = body["violations"][0]["reasons"]
        self.assertEqual([r["code"] for r in reasons], ["LICENSE_NOT_ALLOWED"])

    def test_with_exception_allowed_by_policy(self):
        payload = base_payload(
            components=[component("root", "GPL-2.0-only WITH Classpath-exception-2.0")],
        )
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual(
            body["components"][0]["witness"],
            "GPL-2.0-only WITH Classpath-exception-2.0",
        )

    def test_with_exception_not_allowed_by_policy(self):
        payload = base_payload()
        payload["policy"]["allowedExceptions"] = []
        payload["components"] = [
            component("root", "GPL-2.0-only WITH Classpath-exception-2.0")
        ]
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "non_compliant")
        reasons = body["violations"][0]["reasons"]
        self.assertEqual([r["code"] for r in reasons], ["EXCEPTION_NOT_ALLOWED"])

    def test_component_without_license_violates(self):
        payload = base_payload(components=[{"bomRef": "root"}])
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "non_compliant")
        reasons = body["violations"][0]["reasons"]
        self.assertEqual([r["code"] for r in reasons], ["NO_LICENSE"])

    def test_multiple_license_entries_are_a_disjunction(self):
        payload = base_payload(
            components=[component("root", "GPL-3.0-only", "Apache-2.0")],
        )
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual(body["components"][0]["witness"], "Apache-2.0")

    def test_witness_prefers_fewest_terms_then_lexicographic(self):
        payload = base_payload(
            components=[component("root", "(BSD-3-Clause AND MIT) OR Apache-2.0")],
        )
        status, body = evaluate(payload)
        self.assertEqual(body["components"][0]["witness"], "Apache-2.0")
        payload = base_payload(
            components=[component("root", "BSD-3-Clause AND MIT")],
        )
        status, body = evaluate(payload)
        self.assertEqual(body["components"][0]["witness"], "BSD-3-Clause AND MIT")

    def test_policy_matching_is_case_insensitive(self):
        payload = base_payload(components=[component("root", "mit")])
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual(body["components"][0]["witness"], "mit")


class ClosureTests(unittest.TestCase):
    def graph_payload(self):
        return base_payload(
            components=[
                component("root", "MIT"),
                component("a", "Apache-2.0"),
                component("b", "GPL-2.0-only WITH Classpath-exception-2.0"),
                component("c", "GPL-3.0-only"),  # reachable -> violation
                component("unreachable", "GPL-3.0-only"),  # ignored
            ],
            dependencies=[
                {"ref": "root", "dependsOn": ["a", "b"]},
                {"ref": "a", "dependsOn": ["c"]},
                {"ref": "b", "dependsOn": ["a"]},
                {"ref": "c", "dependsOn": ["root"]},  # cycle back to root
            ],
        )

    def test_only_reachable_components_are_judged(self):
        status, body = evaluate(self.graph_payload())
        self.assertEqual(status, 200)
        judged = {c["bomRef"] for c in body["components"]} | {
            v["bomRef"] for v in body["violations"]
        }
        self.assertEqual(judged, {"root", "a", "b", "c"})
        self.assertEqual(body["summary"]["reachableComponents"], 4)

    def test_cycles_do_not_duplicate_results(self):
        status, body = evaluate(self.graph_payload())
        refs = [c["bomRef"] for c in body["components"]] + [
            v["bomRef"] for v in body["violations"]
        ]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(body["status"], "non_compliant")
        self.assertEqual([v["bomRef"] for v in body["violations"]], ["c"])

    def test_self_dependency_cycle(self):
        payload = base_payload(
            dependencies=[{"ref": "root", "dependsOn": ["root"]}],
        )
        status, body = evaluate(payload)
        self.assertEqual(body["status"], "compliant")
        self.assertEqual(body["summary"]["reachableComponents"], 1)

    def test_results_sorted_by_bomref(self):
        status, body = evaluate(self.graph_payload())
        refs = [c["bomRef"] for c in body["components"]]
        self.assertEqual(refs, sorted(refs))

    def test_input_order_does_not_change_verdict(self):
        payload = self.graph_payload()
        _, first = evaluate(payload)
        rng = random.Random(20261004)
        for _ in range(10):
            shuffled = copy.deepcopy(payload)
            rng.shuffle(shuffled["components"])
            rng.shuffle(shuffled["dependencies"])
            for dep in shuffled["dependencies"]:
                rng.shuffle(dep["dependsOn"])
            rng.shuffle(shuffled["policy"]["allowedLicenses"])
            rng.shuffle(shuffled["policy"]["deniedLicenses"])
            _, again = evaluate(shuffled)
            self.assertEqual(again, first)


class ValidationTests(unittest.TestCase):
    def assert_field_error(self, payload, field, code):
        status, body = evaluate(payload)
        self.assertEqual(status, 400, body)
        self.assertEqual(body["status"], "invalid")
        matches = [
            e for e in body["errors"] if e["field"] == field and e["code"] == code
        ]
        self.assertTrue(
            matches,
            "expected (%s, %s) in %r" % (field, code, body["errors"]),
        )
        return body

    def test_body_must_be_object(self):
        status, body = evaluate([1, 2, 3])
        self.assertEqual(status, 400)
        self.assertEqual(body["errors"][0]["field"], "$")

    def test_root_required_and_known(self):
        self.assert_field_error({"components": []}, "root", "REQUIRED")
        self.assert_field_error(
            base_payload(root="ghost"), "root", "MISSING_REFERENCE"
        )

    def test_components_required(self):
        self.assert_field_error({"root": "root"}, "components", "REQUIRED")

    def test_duplicate_bomref(self):
        payload = base_payload(
            components=[component("root", "MIT"), component("root", "MIT")]
        )
        self.assert_field_error(payload, "components[1].bomRef", "DUPLICATE_BOM_REF")

    def test_component_limit(self):
        payload = base_payload(
            root="c0",
            components=[component("c%d" % i, "MIT") for i in range(201)],
        )
        self.assert_field_error(payload, "components", "TOO_MANY_COMPONENTS")

    def test_expression_parse_error_reports_field(self):
        payload = base_payload(components=[component("root", "MIT AND (")])
        self.assert_field_error(
            payload, "components[0].licenses[0].expression", "EXPRESSION_PARSE_ERROR"
        )

    def test_invalid_exception_reports_field(self):
        payload = base_payload(
            components=[component("root", "MIT WITH No-Such-Exception")]
        )
        self.assert_field_error(
            payload, "components[0].licenses[0].expression", "INVALID_EXCEPTION"
        )

    def test_missing_dependency_references(self):
        payload = base_payload(
            dependencies=[
                {"ref": "ghost", "dependsOn": ["root"]},
                {"ref": "root", "dependsOn": ["ghost"]},
            ]
        )
        self.assert_field_error(payload, "dependencies[0].ref", "MISSING_REFERENCE")
        self.assert_field_error(
            payload, "dependencies[1].dependsOn[0]", "MISSING_REFERENCE"
        )

    def test_policy_exception_must_be_known(self):
        payload = base_payload()
        payload["policy"]["allowedExceptions"] = [
            {"license": "MIT", "exception": "Invented-Exception"}
        ]
        self.assert_field_error(
            payload, "policy.allowedExceptions[0].exception", "INVALID_EXCEPTION"
        )

    def test_invalid_types_are_field_errors(self):
        payload = base_payload(components="nope")
        self.assert_field_error(payload, "components", "INVALID_TYPE")
        payload = base_payload(dependencies="nope")
        self.assert_field_error(payload, "dependencies", "INVALID_TYPE")
        payload = base_payload()
        payload["policy"]["allowedLicenses"] = "MIT"
        self.assert_field_error(payload, "policy.allowedLicenses", "INVALID_TYPE")

    def test_errors_sorted_by_field(self):
        payload = base_payload(
            root="ghost",
            components=[component("root", "MIT AND ("), component("root", "MIT")],
        )
        status, body = evaluate(payload)
        fields = [e["field"] for e in body["errors"]]
        self.assertEqual(fields, sorted(fields))

    def test_license_id_shorthand_and_string_entries(self):
        payload = base_payload(
            components=[
                {"bomRef": "root", "licenses": [{"license": {"id": "MIT"}}]},
                {"bomRef": "child", "licenses": ["Apache-2.0"]},
            ],
            dependencies=[{"ref": "root", "dependsOn": ["child"]}],
        )
        status, body = evaluate(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "compliant")
        witnesses = {c["bomRef"]: c["witness"] for c in body["components"]}
        self.assertEqual(witnesses, {"root": "MIT", "child": "Apache-2.0"})


if __name__ == "__main__":
    unittest.main()
