import unittest

from app.spdx_expr import And, License, Or, parse_expression


def parse(text):
    ast, err = parse_expression(text)
    assert err is None, "unexpected parse error for %r: %s" % (text, err)
    return ast


class ParseTests(unittest.TestCase):
    def test_simple_identifier(self):
        self.assertEqual(parse("MIT"), License("MIT"))

    def test_identifier_shapes(self):
        self.assertEqual(parse("Apache-2.0"), License("Apache-2.0"))
        self.assertEqual(parse("BSD-3-Clause"), License("BSD-3-Clause"))
        self.assertEqual(parse("LicenseRef-ACME-Proprietary"), License("LicenseRef-ACME-Proprietary"))
        self.assertEqual(parse("0BSD"), License("0BSD"))

    def test_or_later_suffix(self):
        self.assertEqual(parse("Apache-2.0+"), License("Apache-2.0+"))

    def test_and_binds_tighter_than_or(self):
        ast = parse("MIT OR Apache-2.0 AND BSD-3-Clause")
        self.assertIsInstance(ast, Or)
        self.assertEqual(ast.options[0], License("MIT"))
        self.assertIsInstance(ast.options[1], And)
        self.assertEqual(
            ast.options[1].terms, (License("Apache-2.0"), License("BSD-3-Clause"))
        )

    def test_parentheses_override_precedence(self):
        ast = parse("(MIT OR Apache-2.0) AND BSD-3-Clause")
        self.assertIsInstance(ast, And)
        self.assertIsInstance(ast.terms[0], Or)
        self.assertEqual(ast.terms[1], License("BSD-3-Clause"))

    def test_nested_parentheses(self):
        ast = parse("((MIT))")
        self.assertEqual(ast, License("MIT"))

    def test_with_exception(self):
        self.assertEqual(
            parse("GPL-2.0-only WITH Classpath-exception-2.0"),
            License("GPL-2.0-only", "Classpath-exception-2.0"),
        )

    def test_operators_are_case_insensitive(self):
        ast = parse("mit and apache-2.0 or bsd-3-clause")
        self.assertIsInstance(ast, Or)
        self.assertIsInstance(ast.options[0], And)

    def test_whitespace_tolerance(self):
        self.assertEqual(parse("  MIT\tOR\n Apache-2.0 "), parse("MIT OR Apache-2.0"))

    def test_parse_errors(self):
        cases = [
            "",
            "   ",
            "(",
            ")",
            "MIT AND",
            "AND MIT",
            "MIT OR OR Apache-2.0",
            "MIT Apache-2.0",
            "(MIT OR Apache-2.0",
            "MIT)",
            "MIT & Apache-2.0",
            "MIT WITH Classpath-exception-2.0 WITH Classpath-exception-2.0",
            "(MIT OR Apache-2.0) WITH Classpath-exception-2.0",
        ]
        for text in cases:
            with self.subTest(text=text):
                ast, err = parse_expression(text)
                self.assertIsNone(ast)
                self.assertIsNotNone(err)
                self.assertEqual(err.code, "EXPRESSION_PARSE_ERROR")

    def test_invalid_exceptions(self):
        for text in ("MIT WITH", "MIT WITH AND Apache-2.0", "MIT WITH No-Such-Exception"):
            with self.subTest(text=text):
                ast, err = parse_expression(text)
                self.assertIsNone(ast)
                self.assertIsNotNone(err)
                self.assertEqual(err.code, "INVALID_EXCEPTION")

    def test_exception_names_are_case_insensitive_against_known_list(self):
        ast, err = parse_expression("GPL-2.0-only WITH classpath-EXCEPTION-2.0")
        self.assertIsNone(err)
        self.assertEqual(ast.exception, "classpath-EXCEPTION-2.0")


if __name__ == "__main__":
    unittest.main()
