"""Iterative RFC 8259 parser that keeps duplicate keys and source positions.

Nodes are lightweight (``__slots__``); the JSON path and line/column are computed lazily so
parsing a multi-megabyte document stays fast.
"""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any

MAX_DEPTH = 512

OBJECT, ARRAY, STRING, NUMBER, TRUE, FALSE, NULL = (
    "object",
    "array",
    "string",
    "number",
    "true",
    "false",
    "null",
)

_WS = re.compile(r"[ \t\n\r]*")
_TOKEN = re.compile(
    r'[ \t\n\r]*(?:("[^"\\\x00-\x1f]*(?:\\.[^"\\\x00-\x1f]*)*")'
    r"|(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)"
    r"|([{}\[\],:])"
    r"|(true|false|null))",
    re.DOTALL,
)
_STR = re.compile(r'"[^"\\\x00-\x1f]*(?:\\.[^"\\\x00-\x1f]*)*"', re.DOTALL)
_NUM = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_ESC = re.compile(r"\\(.)?", re.DOTALL)
_HEX4 = re.compile(r"[0-9a-fA-F]{4}")
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_LITERALS = {"true": TRUE, "false": FALSE, "null": NULL}


class Node:
    __slots__ = ("children", "end", "kind", "kstart", "parent", "ref", "start", "value")

    def __init__(
        self,
        kind: str,
        start: int,
        end: int,
        parent: Node | None,
        ref: str | int | None,
        value: str | None,
    ) -> None:
        self.kind = kind
        self.start = start
        self.end = end
        self.parent = parent
        self.ref = ref  # key (str) when parent is an object, index (int) when parent is an array
        self.value = value  # decoded string, or number lexeme
        self.children: list[Node] | None = None
        self.kstart = 0  # offset of the key token when the parent is an object

    @property
    def is_container(self) -> bool:
        return self.kind == OBJECT or self.kind == ARRAY

    @property
    def path(self) -> str:
        return node_path(self)


def path_segment(ref: str | int) -> str:
    if isinstance(ref, int):
        return f"[{ref}]"
    if _IDENT.match(ref):
        return f".{ref}"
    return "[" + json.dumps(ref, ensure_ascii=False) + "]"


def node_path(node: Node) -> str:
    parts: list[str] = []
    cur: Node | None = node
    while cur is not None and cur.parent is not None:
        assert cur.ref is not None
        parts.append(path_segment(cur.ref))
        cur = cur.parent
    parts.append("$")
    parts.reverse()
    return "".join(parts)


class LineIndex:
    """Maps character offsets to 1-based (line, column)."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts: list[int] | None = None

    def locate(self, offset: int) -> tuple[int, int]:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in re.finditer("\n", self._text)]
        i = bisect_right(self._starts, offset) - 1
        return i + 1, offset - self._starts[i] + 1


@dataclass(slots=True)
class ParseError:
    message: str
    line: int
    column: int
    offset: int


@dataclass(slots=True)
class ParseResult:
    text: str
    root: Node | None = None
    error: ParseError | None = None
    too_deep: bool = False
    nodes: int = 0
    depth: int = 0
    dup_objects: list[Node] = field(default_factory=list)
    lines: LineIndex | None = None

    @property
    def valid(self) -> bool:
        return self.error is None and not self.too_deep


class _Fail(Exception):
    def __init__(self, offset: int, message: str) -> None:
        self.offset = offset
        self.message = message


class _TooDeep(Exception):
    pass


def _string_error(text: str, pos: int) -> _Fail:
    """Diagnose why a string starting at ``pos`` does not match the string pattern."""
    i = pos + 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            break
        if c == "\\":
            i += 2
            continue
        if c < " ":
            return _Fail(i, "Control character in string must be escaped")
        i += 1
    else:
        return _Fail(pos, "Unterminated string")
    return _Fail(pos, "Invalid string")  # pragma: no cover


def _decode_string(text: str, start: int, end: int) -> str:
    raw = text[start + 1 : end - 1]
    if "\\" not in raw:
        return raw
    for m in _ESC.finditer(raw):
        ch = m.group(1)
        if ch is None or (ch not in '"\\/bfnrtu'):
            raise _Fail(start + 1 + m.start(), "Invalid escape sequence")
        if ch == "u" and not _HEX4.match(raw, m.end()):
            raise _Fail(start + 1 + m.start(), "Invalid unicode escape")
    return json.loads(text[start:end])  # type: ignore[no-any-return]


def _after_fail(text: str, tstart: int, num_end: int, top: Node | None) -> _Fail:
    if tstart == num_end and text[tstart] in "0123456789.eE+-":
        return _Fail(tstart, "Invalid number")
    closer = "}" if top is not None and top.kind == OBJECT else "]"
    return _Fail(tstart, f"Expected ',' or '{closer}'")


def _diagnose(text: str, pos: int) -> _Fail:
    """Explain why no token matches at ``pos`` (whitespace is skipped first)."""
    p = _WS.match(text, pos).end()  # type: ignore[union-attr]
    if p >= len(text):
        return _Fail(p, "Unexpected end of input")
    c = text[p]
    if c == '"':
        return _string_error(text, p)
    if c == "-" or "0" <= c <= "9":
        return _Fail(p, "Invalid number")
    return _Fail(p, f"Unexpected token {c!r}")


def parse(text: str, max_depth: int = MAX_DEPTH) -> ParseResult:
    result = ParseResult(text=text, lines=LineIndex(text))
    try:
        _parse(text, max_depth, result)
    except _Fail as f:
        assert result.lines is not None
        line, col = result.lines.locate(f.offset)
        result.error = ParseError(f.message, line, col, f.offset)
        result.root = None
    except _TooDeep:
        result.too_deep = True
        result.root = None
    return result


_VALUE, _VALUE_OR_END, _KEY_OR_END, _KEY, _COLON, _AFTER = range(6)


def _parse(text: str, max_depth: int, result: ParseResult) -> None:
    tok = _TOKEN.match
    n = len(text)
    stack: list[Node] = []
    dup_objects = result.dup_objects
    nodes = 0
    max_d = 0
    pos = 0
    state = _VALUE
    pkey: str | None = None
    pkoff = 0
    top: Node | None = None  # current open container
    root: Node | None = None
    num_end = -1

    if text.startswith("\ufeff"):
        raise _Fail(0, "Unexpected byte order mark")

    while True:
        m = tok(text, pos)
        if m is None:
            raise _diagnose(text, pos)
        g = m.lastindex
        end = m.end()
        if g == 3:
            p = m.group(3)
            tstart = end - 1
        else:
            assert g is not None
            tstart = m.start(g)

        # ------------------------------------------------------------------ closers
        if state == _AFTER:
            if g != 3:
                raise _after_fail(text, tstart, num_end, top)
            assert top is not None
            if p == ",":
                state = _KEY if top.kind == OBJECT else _VALUE
            elif (p == "}" and top.kind == OBJECT) or (p == "]" and top.kind == ARRAY):
                top.end = end
                if p == "}":
                    ch = top.children
                    assert ch is not None
                    if len(ch) > 1 and len({c.ref for c in ch}) != len(ch):
                        dup_objects.append(top)
                stack.pop()
                top = stack[-1] if stack else None
                if top is None:
                    pos = end
                    break
            else:
                raise _after_fail(text, tstart, num_end, top)
            pos = end
            continue

        if state == _COLON:
            if g != 3 or p != ":":
                raise _Fail(tstart, "Expected ':' after object key")
            state = _VALUE
            pos = end
            continue

        if state in (_KEY, _KEY_OR_END):
            if g == 1:
                pkey = _decode_string(text, tstart, end)
                pkoff = tstart
                state = _COLON
                pos = end
                continue
            if g == 3 and p == "}" and state == _KEY_OR_END:
                assert top is not None
                top.end = end
                stack.pop()
                top = stack[-1] if stack else None
                pos = end
                if top is None:
                    break
                state = _AFTER
                continue
            if g == 3 and p == "}":
                raise _Fail(tstart, "Trailing comma is not allowed")
            raise _Fail(tstart, "Expected string key")

        # ------------------------------------------------------------------ values
        if g == 3:
            if p == "]" and state == _VALUE_OR_END:
                assert top is not None
                top.end = end
                stack.pop()
                top = stack[-1] if stack else None
                pos = end
                if top is None:
                    break
                state = _AFTER
                continue
            if p == "]" and top is not None and top.kind == ARRAY:
                raise _Fail(tstart, "Trailing comma is not allowed")
            if p != "{" and p != "[":
                raise _Fail(tstart, f"Unexpected token {p!r}")

        if top is None:
            ref: str | int | None = None
        elif top.kind == OBJECT:
            ref = pkey
        else:
            assert top.children is not None
            ref = len(top.children)

        if g == 1:
            node = Node(STRING, tstart, end, top, ref, _decode_string(text, tstart, end))
        elif g == 2:
            node = Node(NUMBER, tstart, end, top, ref, m.group(2))
            num_end = end
        elif g == 4:
            lit = m.group(4)
            node = Node(_LITERALS[lit], tstart, end, top, ref, None)
        else:
            node = Node(OBJECT if p == "{" else ARRAY, tstart, end, top, ref, None)
            node.children = []
        nodes += 1
        if top is None:
            root = node
        else:
            assert top.children is not None
            node.kstart = pkoff
            top.children.append(node)
        pos = end
        if g == 3:
            stack.append(node)
            top = node
            if len(stack) > max_d:
                max_d = len(stack)
                if max_d > max_depth:
                    raise _TooDeep
            state = _KEY_OR_END if p == "{" else _VALUE_OR_END
        elif top is None:
            break
        else:
            state = _AFTER

    # trailing content check
    if _WS.match(text, pos).end() < n:  # type: ignore[union-attr]
        p2 = _WS.match(text, pos).end()  # type: ignore[union-attr]
        if p2 == num_end and text[p2] in "0123456789.eE+-":
            raise _Fail(p2, "Invalid number")
        raise _Fail(p2, "Unexpected data after top-level value")
    result.root = root
    result.nodes = nodes
    result.depth = max_d


def effective_members(obj: Node) -> list[tuple[str, Node]]:
    """Members with JSON.parse semantics: the last duplicate wins, first-appearance order."""
    assert obj.children is not None
    last: dict[str, Node] = {}
    for child in obj.children:
        last[child.ref] = child  # type: ignore[index]
    return list(last.items())


def parse_error_dict(result: ParseResult) -> dict[str, Any] | None:
    if result.too_deep:
        return {"message": "Nesting too deep", "line": 1, "column": 1}
    if result.error is None:
        return None
    return {
        "message": result.error.message,
        "line": result.error.line,
        "column": result.error.column,
    }
