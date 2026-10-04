"""SBOM 许可证策略裁决引擎。

职责：
* 解析 SPDX 许可证表达式（标识符、括号、AND / OR / WITH，AND 优先级高于 OR）；
* 沿依赖图计算从根组件可达的组件闭包（环安全、不重复）；
* 按允许 / 拒绝 / 例外对策略逐组件裁决，拒绝项优先；
* 对缺失引用、表达式错误、非法例外等按字段返回错误。

本模块只依赖 Python 标准库，保证离线构建。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

MAX_COMPONENTS = 200


# --------------------------------------------------------------------------- #
# 错误承载
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FieldError:
    """按字段返回的请求错误。"""

    field_path: str
    code: str
    message: str

    def to_dict(self) -> dict:
        return {"field": self.field_path, "code": self.code, "message": self.message}


class ValidationFailed(Exception):
    """请求级校验失败（HTTP 400）。"""

    def __init__(self, errors: list[FieldError]):
        self.errors = errors
        super().__init__("; ".join(e.message for e in errors))


# --------------------------------------------------------------------------- #
# SPDX 表达式词法 / 语法
# --------------------------------------------------------------------------- #


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]*\+?|[()]")


@dataclass(frozen=True)
class Token:
    kind: str  # IDENT | AND | OR | WITH | LPAREN | RPAREN
    value: str
    pos: int


def tokenize(expression: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    n = len(expression)
    while pos < n:
        if expression[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(expression, pos)
        if not m or m.start() != pos:
            raise _ExpressionError(f"非法字符 {expression[pos]!r}", pos)
        text = m.group(0)
        if text == "(":
            tokens.append(Token("LPAREN", text, pos))
        elif text == ")":
            tokens.append(Token("RPAREN", text, pos))
        elif text == "AND":
            tokens.append(Token("AND", text, pos))
        elif text == "OR":
            tokens.append(Token("OR", text, pos))
        elif text == "WITH":
            tokens.append(Token("WITH", text, pos))
        else:
            tokens.append(Token("IDENT", text, pos))
        pos = m.end()
    return tokens


class _ExpressionError(ValueError):
    def __init__(self, message: str, pos: Optional[int] = None):
        self.pos = pos
        super().__init__(message)


# --------------------------------------------------------------------------- #
# AST
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LicenseNode:
    license_id: str


@dataclass(frozen=True)
class WithNode:
    license_id: str
    exception_id: str


@dataclass(frozen=True)
class AndNode:
    items: tuple["Node", ...]


@dataclass(frozen=True)
class OrNode:
    items: tuple["Node", ...]


Node = LicenseNode | WithNode | AndNode | OrNode


class _Parser:
    """递归下降解析器。

    or_expr  := and_expr (OR and_expr)*
    and_expr := factor  (AND factor)*
    factor   := IDENT [WITH IDENT] | LPAREN or_expr RPAREN
    """

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.i = 0

    def _peek(self) -> Optional[Token]:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _take(self) -> Token:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> Node:
        if not self.tokens:
            raise _ExpressionError("空表达式", 0)
        node = self._parse_or()
        if self._peek() is not None:
            tok = self._peek()
            raise _ExpressionError(f"多余的记号 {tok.value!r}", tok.pos)
        return node

    def _parse_or(self) -> Node:
        items = [self._parse_and()]
        while self._peek() is not None and self._peek().kind == "OR":
            self._take()
            items.append(self._parse_and())
        return items[0] if len(items) == 1 else OrNode(tuple(items))

    def _parse_and(self) -> Node:
        items = [self._parse_factor()]
        while self._peek() is not None and self._peek().kind == "AND":
            self._take()
            items.append(self._parse_factor())
        return items[0] if len(items) == 1 else AndNode(tuple(items))

    def _parse_factor(self) -> Node:
        tok = self._peek()
        if tok is None:
            raise _ExpressionError("表达式意外结束")
        if tok.kind == "LPAREN":
            self._take()
            node = self._parse_or()
            close = self._peek()
            if close is None or close.kind != "RPAREN":
                raise _ExpressionError("缺少右括号 ')'", tok.pos)
            self._take()
            return node
        if tok.kind != "IDENT":
            raise _ExpressionError(f"需要许可证标识符，却遇到 {tok.value!r}", tok.pos)
        self._take()
        nxt = self._peek()
        if nxt is not None and nxt.kind == "WITH":
            self._take()
            exc_tok = self._peek()
            if exc_tok is None or exc_tok.kind != "IDENT":
                pos = nxt.pos
                raise _ExpressionError("WITH 后必须跟随例外标识符", pos)
            self._take()
            return WithNode(tok.value, exc_tok.value)
        return LicenseNode(tok.value)


def parse_expression(expression: str) -> Node:
    return _Parser(tokenize(expression)).parse()


# --------------------------------------------------------------------------- #
# 策略裁决
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Policy:
    allowed: frozenset[str]
    denied: frozenset[str]
    exception_pairs: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class Verdict:
    ok: bool
    witnesses: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()


def _witness(node: LicenseNode | WithNode) -> str:
    if isinstance(node, WithNode):
        return f"{node.license_id} WITH {node.exception_id}"
    return node.license_id


def _evaluate_node(node: Node, policy: _Policy) -> Verdict:
    if isinstance(node, LicenseNode):
        lid = node.license_id
        if lid in policy.denied:  # 拒绝项优先
            return Verdict(False, (), (f"许可证被策略拒绝: {lid}",))
        if lid in policy.allowed:
            return Verdict(True, (lid,), ())
        return Verdict(False, (), (f"许可证不在允许清单: {lid}",))

    if isinstance(node, WithNode):
        lid, exc = node.license_id, node.exception_id
        if lid in policy.denied:  # 拒绝项优先，例外也无法豁免
            return Verdict(False, (), (f"许可证被策略拒绝: {lid}",))
        if (lid, exc) in policy.exception_pairs:
            return Verdict(True, (_witness(node),), ())
        return Verdict(
            False,
            (),
            (f"WITH 组合未被政策明确允许: {lid} WITH {exc}",),
        )

    if isinstance(node, AndNode):
        witnesses: list[str] = []
        reasons: list[str] = []
        ok = True
        for child in node.items:
            v = _evaluate_node(child, policy)
            if v.ok:
                witnesses.extend(v.witnesses)
            else:
                ok = False
                reasons.extend(v.reasons)
        return Verdict(ok, tuple(sorted(set(witnesses))), tuple(_dedupe(reasons)))

    # OrNode：至少一支合规即可；取第一支合规分支作为见证。
    assert isinstance(node, OrNode)
    all_reasons: list[str] = []
    for idx, child in enumerate(node.items, start=1):
        v = _evaluate_node(child, policy)
        if v.ok:
            return Verdict(True, tuple(sorted(set(v.witnesses))), ())
        all_reasons.extend(f"OR 分支 {idx}: {r}" for r in v.reasons)
    return Verdict(False, (), tuple(_dedupe(all_reasons)))


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------- #
# 请求校验与整体评估
# --------------------------------------------------------------------------- #


@dataclass
class _Component:
    bom_ref: str
    name: Optional[str]
    license_expression: str
    ast: Node


def _require_str(value, field_path: str, errors: list[FieldError]) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        errors.append(FieldError(field_path, "invalid_type", "必须是非空字符串"))
        return None
    return value


def _validate_and_build(payload: object) -> tuple[list[_Component], dict[str, list[str]], str, _Policy]:
    errors: list[FieldError] = []

    if not isinstance(payload, dict):
        raise ValidationFailed(
            [FieldError("body", "invalid_type", "请求体必须是 JSON 对象")]
        )

    root = _require_str(payload.get("root_component"), "root_component", errors)

    # ---- 组件 -------------------------------------------------------------
    raw_components = payload.get("components")
    if not isinstance(raw_components, list):
        errors.append(FieldError("components", "invalid_type", "必须是组件数组"))
        raw_components = []
    if len(raw_components) > MAX_COMPONENTS:
        errors.append(
            FieldError(
                "components",
                "too_many_components",
                f"组件数量 {len(raw_components)} 超过上限 {MAX_COMPONENTS}",
            )
        )

    components: list[_Component] = []
    bom_refs: set[str] = set()
    for i, raw in enumerate(raw_components):
        base = f"components[{i}]"
        if not isinstance(raw, dict):
            errors.append(FieldError(base, "invalid_type", "组件必须是对象"))
            continue
        bom_ref = _require_str(raw.get("bom_ref"), f"{base}.bom_ref", errors)
        if bom_ref is not None:
            if bom_ref in bom_refs:
                errors.append(
                    FieldError(
                        f"{base}.bom_ref",
                        "duplicate_bom_ref",
                        f"bom_ref 重复: {bom_ref}",
                    )
                )
            else:
                bom_refs.add(bom_ref)
        expr = _require_str(
            raw.get("license_expression"), f"{base}.license_expression", errors
        )
        ast: Optional[Node] = None
        if expr is not None:
            try:
                ast = parse_expression(expr)
            except _ExpressionError as exc:
                location = f"（位置 {exc.pos}）" if exc.pos is not None else ""
                errors.append(
                    FieldError(
                        f"{base}.license_expression",
                        "invalid_expression",
                        f"SPDX 表达式错误{location}: {exc}",
                    )
                )
        name = raw.get("name")
        if name is not None and not isinstance(name, str):
            errors.append(FieldError(f"{base}.name", "invalid_type", "name 必须是字符串"))
        if bom_ref is not None and ast is not None:
            components.append(
                _Component(bom_ref, name if isinstance(name, str) else None, expr, ast)
            )

    # ---- 依赖 -------------------------------------------------------------
    raw_deps = payload.get("dependencies", [])
    if not isinstance(raw_deps, list):
        errors.append(FieldError("dependencies", "invalid_type", "必须是依赖关系数组"))
        raw_deps = []

    edges: dict[str, list[str]] = {}
    for i, raw in enumerate(raw_deps):
        base = f"dependencies[{i}]"
        if not isinstance(raw, dict):
            errors.append(FieldError(base, "invalid_type", "依赖关系必须是对象"))
            continue
        ref = _require_str(raw.get("ref"), f"{base}.ref", errors)
        depends_on = raw.get("depends_on", [])
        if not isinstance(depends_on, list) or not all(
            isinstance(x, str) and x for x in depends_on
        ):
            errors.append(
                FieldError(
                    f"{base}.depends_on", "invalid_type", "必须是非空 bomRef 字符串数组"
                )
            )
            depends_on = []
        if ref is not None:
            if ref not in bom_refs:
                errors.append(
                    FieldError(
                        f"{base}.ref",
                        "unresolved_reference",
                        f"依赖声明引用了不存在的 bomRef: {ref}",
                    )
                )
            else:
                edges.setdefault(ref, [])
                for j, dep in enumerate(depends_on):
                    if dep not in bom_refs:
                        errors.append(
                            FieldError(
                                f"{base}.depends_on[{j}]",
                                "unresolved_reference",
                                f"引用了不存在的 bomRef: {dep}",
                            )
                        )
                    else:
                        edges.setdefault(ref, []).append(dep)

    if root is not None and root not in bom_refs:
        errors.append(
            FieldError(
                "root_component",
                "unresolved_reference",
                f"根组件 bomRef 不存在: {root}",
            )
        )

    # ---- 策略 -------------------------------------------------------------
    def _str_list(value, field_path: str) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
            errors.append(FieldError(field_path, "invalid_type", "必须是非空字符串数组"))
            return []
        return list(value)

    allowed = frozenset(_str_list(payload.get("allowed_licenses"), "allowed_licenses"))
    denied = frozenset(_str_list(payload.get("denied_licenses"), "denied_licenses"))

    raw_pairs = payload.get("allowed_exceptions", [])
    if raw_pairs is None:
        raw_pairs = []
    if not isinstance(raw_pairs, list):
        errors.append(FieldError("allowed_exceptions", "invalid_type", "必须是例外对数组"))
        raw_pairs = []
    pairs: set[tuple[str, str]] = set()
    for i, raw in enumerate(raw_pairs):
        base = f"allowed_exceptions[{i}]"
        if not isinstance(raw, dict):
            errors.append(FieldError(base, "invalid_type", "例外对必须是对象"))
            continue
        lic = _require_str(raw.get("license"), f"{base}.license", errors)
        exc = _require_str(raw.get("exception"), f"{base}.exception", errors)
        if lic is not None and exc is not None:
            pairs.add((lic, exc))

    if errors:
        raise ValidationFailed(errors)

    policy = _Policy(allowed, denied, frozenset(pairs))
    return components, edges, root, policy


def _reachable(root: str, edges: dict[str, list[str]]) -> list[str]:
    """从根出发的可达闭包（DFS，visited 去重，环安全）。"""
    seen: set[str] = {root}
    order: list[str] = []
    stack: list[str] = [root]
    while stack:
        ref = stack.pop()
        order.append(ref)
        for dep in edges.get(ref, []):
            if dep not in seen:
                seen.add(dep)
                stack.append(dep)
    return order


def evaluate(payload: object) -> dict:
    """评估一个 /api/sboms/evaluate 请求体，返回可 JSON 序列化的响应。

    返回 (http_status, body)。
    """
    components, edges, root, policy = _validate_and_build(payload)
    by_ref = {c.bom_ref: c for c in components}

    reachable = _reachable(root, edges)  # 仅裁决从根可达的闭包

    evaluated: list[dict] = []
    violations: list[dict] = []
    compliant = True
    for ref in sorted(reachable):
        comp = by_ref[ref]
        verdict = _evaluate_node(comp.ast, policy)
        evaluated.append(
            {
                "bom_ref": comp.bom_ref,
                "name": comp.name,
                "license_expression": comp.license_expression,
                "witnesses": list(verdict.witnesses),
            }
        )
        if not verdict.ok:
            compliant = False
            violations.append(
                {
                    "bom_ref": comp.bom_ref,
                    "license_expression": comp.license_expression,
                    "reasons": list(verdict.reasons),
                }
            )

    return {
        "compliant": compliant,
        "root_component": root,
        "evaluated_components": evaluated,
        "violations": violations,
    }, 200


def validation_error_body(errors: list[FieldError]) -> dict:
    return {
        "error": {
            "code": "validation_error",
            "message": "请求未通过校验",
            "fields": [e.to_dict() for e in errors],
        }
    }
