from __future__ import annotations

import json

import pytest

from app.domain.analysis.positional_parser import (
    MAX_DEPTH,
    effective_members,
    parse,
    parse_error_dict,
    path_segment,
)


def ok(text: str):  # type: ignore[no-untyped-def]
    result = parse(text)
    assert result.valid, result.error
    return result


@pytest.mark.parametrize(
    "text",
    [
        "{}",
        "[]",
        "1",
        "-0",
        "1.5e+10",
        '"x"',
        "true",
        "false",
        "null",
        '  [1, 2 , {"a": [null]}]\n',
        '{"a":{"b":{"c":[]}}}',
        '"\\u00e9\\n\\t\\"\\\\\\/"',
        "[1E3, 0.5, -1.25e-2]",
        '"emoji 😀"',
    ],
)
def test_valid_documents_match_stdlib(text: str) -> None:
    result = ok(text)
    json.loads(text)
    assert result.root is not None


@pytest.mark.parametrize(
    ("text", "message", "line", "column"),
    [
        ("", "Unexpected end of input", 1, 1),
        ("   ", "Unexpected end of input", 1, 4),
        ("{", "Unexpected end of input", 1, 2),
        ('{"a"', "Unexpected end of input", 1, 5),
        ('{"a" 1}', "Expected ':' after object key", 1, 6),
        ('{"a":1,}', "Trailing comma is not allowed", 1, 8),
        ('{"a":1 "b":2}', "Expected ',' or '}'", 1, 8),
        ("[1 2]", "Expected ',' or ']'", 1, 4),
        ("[1,]", "Trailing comma is not allowed", 1, 4),
        ("[1,2", "Unexpected end of input", 1, 5),
        ("{1:2}", "Expected string key", 1, 2),
        ("{'a':1}", 'Unexpected token "\'"', 1, 2),
        ('{"a":}', "Unexpected token '}'", 1, 6),
        ("[,1]", "Unexpected token ','", 1, 2),
        ("[1,,2]", "Unexpected token ','", 1, 4),
        ('"abc', "Unterminated string", 1, 1),
        ('"a\nb"', "Control character in string must be escaped", 1, 3),
        ('"a\\x"', "Invalid escape sequence", 1, 3),
        ('"\\u12G4"', "Invalid unicode escape", 1, 2),
        ("01", "Invalid number", 1, 2),
        ("1.", "Invalid number", 1, 2),
        ("-", "Invalid number", 1, 1),
        ("1e", "Invalid number", 1, 2),
        ("tru", "Unexpected token 't'", 1, 1),
        ("nul", "Unexpected token 'n'", 1, 1),
        ("NaN", "Unexpected token 'N'", 1, 1),
        ("{} x", "Unexpected data after top-level value", 1, 4),
        ("[] []", "Unexpected data after top-level value", 1, 4),
        ("﻿{}", "Unexpected byte order mark", 1, 1),
        ('{\n  "a": 1,\n  "b": ?\n}', "Unexpected token '?'", 3, 8),
        ("[\n1,\n2,\n]", "Trailing comma is not allowed", 4, 1),
    ],
)
def test_syntax_errors_have_positions(text: str, message: str, line: int, column: int) -> None:
    result = parse(text)
    assert not result.valid and result.error is not None
    assert (result.error.message, result.error.line, result.error.column) == (message, line, column)
    assert parse_error_dict(result) == {"message": message, "line": line, "column": column}


def test_duplicate_keys_are_kept_with_positions() -> None:
    text = '{\n  "a": 1,\n  "b": 2,\n  "a": {"x": 3}\n}'
    result = ok(text)
    assert len(result.dup_objects) == 1
    obj = result.dup_objects[0]
    assert obj.children is not None
    a1, _, a2 = obj.children
    assert (a1.ref, a2.ref) == ("a", "a")
    assert result.lines is not None
    assert result.lines.locate(a1.kstart) == (2, 3)
    assert result.lines.locate(a2.kstart) == (4, 3)
    assert text[a2.start : a2.end] == '{"x": 3}'
    # JSON.parse semantics: the last value wins, order of first appearance
    members = effective_members(obj)
    assert [k for k, _ in members] == ["a", "b"]
    assert members[0][1] is a2


def test_no_false_duplicates() -> None:
    assert ok('{"a":1,"b":{"a":2}}').dup_objects == []


def test_paths() -> None:
    result = ok('{"a":[{"b c":1,"d":{"e":null}}],"x-y":2,"":3,"q\\"":4,"1a":5}')
    root = result.root
    assert root is not None and root.children is not None
    arr = root.children[0]
    assert arr.path == "$.a"
    obj = arr.children[0]  # type: ignore[index]
    assert obj.path == "$.a[0]"
    assert obj.children[0].path == '$.a[0]["b c"]'  # type: ignore[index]
    assert obj.children[1].children[0].path == "$.a[0].d.e"  # type: ignore[index]
    assert root.path == "$"
    assert root.children[1].path == '$["x-y"]'
    assert root.children[2].path == '$[""]'
    assert root.children[3].path == '$["q\\""]'
    assert root.children[4].path == '$["1a"]'
    assert path_segment(3) == "[3]" and path_segment("ok_1") == ".ok_1"
    assert path_segment("é") == '["é"]'


def test_unicode_and_escapes() -> None:
    result = ok('{"k\\u00e9y": "\\ud83d\\ude00 \\n"}')
    assert result.root is not None and result.root.children is not None
    child = result.root.children[0]
    assert child.ref == "kéy" and child.value == "😀 \n"


def test_columns_count_characters_not_bytes() -> None:
    result = parse('{"é": 1, "b" 2}')
    assert result.error is not None and result.error.column == 14


def test_depth_limit() -> None:
    deep_ok = "[" * MAX_DEPTH + "]" * MAX_DEPTH
    r = parse(deep_ok)
    assert r.valid and r.depth == MAX_DEPTH
    too_deep = parse("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1))
    assert too_deep.too_deep and not too_deep.valid
    assert parse_error_dict(too_deep)["message"] == "Nesting too deep"  # type: ignore[index]
    assert parse("[" * 100000).too_deep  # never recurses
    assert parse("[" * 10, max_depth=5).too_deep
    assert parse('{"a":' * 600).too_deep


def test_counts() -> None:
    r = ok('{"a":[1,2,{"b":null}],"c":"x"}')
    assert r.nodes == 7 and r.depth == 3
