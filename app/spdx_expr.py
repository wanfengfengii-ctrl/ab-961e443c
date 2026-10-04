"""SPDX license expression parsing.

Supports license identifiers, parentheses, the ``AND`` / ``OR`` / ``WITH``
operators and the ``+`` (or-later) suffix.  ``AND`` binds tighter than
``OR``; operators are matched case-insensitively while identifiers keep
their original case.  ``WITH`` may only follow a license identifier and its
right-hand side must be a known SPDX exception identifier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple

from .spdx_exceptions import SPDX_EXCEPTIONS

PARSE_ERROR = "EXPRESSION_PARSE_ERROR"
INVALID_EXCEPTION = "INVALID_EXCEPTION"


class ExprError(Exception):
    """A single, field-reportable expression problem."""

    def __init__(self, code: str, message: str, position: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.position = position


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class License:
    id: str
    exception: Optional[str] = None


@dataclass(frozen=True)
class And:
    terms: Tuple[object, ...]


@dataclass(frozen=True)
class Or:
    options: Tuple[object, ...]


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:\-]*\+?")
_KEYWORDS = {"AND": "AND", "OR": "OR", "WITH": "WITH"}


@dataclass(frozen=True)
class _Token:
    kind: str  # IDENT | AND | OR | WITH | LPAREN | RPAREN
    text: str
    pos: int


def _tokenize(text: str) -> list:
    tokens = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append(_Token("LPAREN", ch, i))
            i += 1
            continue
        if ch == ")":
            tokens.append(_Token("RPAREN", ch, i))
            i += 1
            continue
        match = _IDENT_RE.match(text, i)
        if match:
            word = match.group(0)
            kind = _KEYWORDS.get(word.upper(), "IDENT")
            tokens.append(_Token(kind, word, i))
            i = match.end()
            continue
        raise ExprError(
            PARSE_ERROR,
            "unexpected character %r at position %d" % (ch, i),
            i,
        )
    return tokens


# ---------------------------------------------------------------------------
# Parser (recursive descent)
# ---------------------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: list, text: str):
        self._tokens = tokens
        self._text = text
        self._i = 0

    def _peek(self) -> Optional[_Token]:
        return self._tokens[self._i] if self._i < len(self._tokens) else None

    def _advance(self) -> Optional[_Token]:
        tok = self._peek()
        self._i += 1
        return tok

    def parse(self):
        if not self._tokens:
            raise ExprError(PARSE_ERROR, "expression is empty", 0)
        node = self._parse_or()
        leftover = self._peek()
        if leftover is not None:
            raise ExprError(
                PARSE_ERROR,
                "unexpected %r at position %d" % (leftover.text, leftover.pos),
                leftover.pos,
            )
        return node

    def _parse_or(self):
        options = [self._parse_and()]
        while self._peek() is not None and self._peek().kind == "OR":
            self._advance()
            options.append(self._parse_and())
        return options[0] if len(options) == 1 else Or(tuple(options))

    def _parse_and(self):
        terms = [self._parse_with()]
        while self._peek() is not None and self._peek().kind == "AND":
            self._advance()
            terms.append(self._parse_with())
        return terms[0] if len(terms) == 1 else And(tuple(terms))

    def _parse_with(self):
        node = self._parse_primary()
        tok = self._peek()
        if tok is None or tok.kind != "WITH":
            return node
        if not isinstance(node, License):
            raise ExprError(
                PARSE_ERROR,
                "WITH cannot follow a parenthesized expression (position %d)" % tok.pos,
                tok.pos,
            )
        self._advance()
        exc = self._peek()
        if exc is None or exc.kind != "IDENT":
            raise ExprError(
                INVALID_EXCEPTION,
                "expected an exception identifier after WITH (position %d)" % tok.pos,
                tok.pos,
            )
        self._advance()
        if exc.text.lower() not in SPDX_EXCEPTIONS:
            raise ExprError(
                INVALID_EXCEPTION,
                "unknown exception %r at position %d" % (exc.text, exc.pos),
                exc.pos,
            )
        return License(node.id, exc.text)

    def _parse_primary(self):
        tok = self._peek()
        if tok is None:
            raise ExprError(
                PARSE_ERROR, "unexpected end of expression", len(self._text)
            )
        if tok.kind == "IDENT":
            self._advance()
            return License(tok.text)
        if tok.kind == "LPAREN":
            self._advance()
            node = self._parse_or()
            closing = self._peek()
            if closing is None or closing.kind != "RPAREN":
                pos = closing.pos if closing is not None else len(self._text)
                raise ExprError(PARSE_ERROR, "expected ')' at position %d" % pos, pos)
            self._advance()
            return node
        raise ExprError(
            PARSE_ERROR,
            "unexpected %r at position %d" % (tok.text, tok.pos),
            tok.pos,
        )


def parse_expression(text: str):
    """Parse ``text`` into an AST.

    Returns ``(ast, None)`` on success or ``(None, ExprError)`` on failure;
    never raises.
    """
    try:
        tokens = _tokenize(text)
        return _Parser(tokens, text).parse(), None
    except ExprError as err:
        return None, err
