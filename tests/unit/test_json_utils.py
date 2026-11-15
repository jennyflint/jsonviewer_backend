from __future__ import annotations

import pytest

from app.lib.errors import PayloadTooLarge, Unprocessable
from app.lib.json_utils import (
    auto_title,
    canonical_number,
    canonicalize,
    content_hash,
    make_preview,
    prepare_content,
    sha256_hex,
    strip_bom,
    utf8_size,
)


def test_canonical_form_ignores_formatting_and_key_order() -> None:
    a = '{"b": [1, 2.0, {"z": 1, "y": null}], "a": "é"}'
    b = '{\n "a":"é",\n"b":[1,2,{"y":null,"z":1}]}'
    assert canonicalize(a) == canonicalize(b) == '{"a":"é","b":[1,2,{"y":null,"z":1}]}'
    assert content_hash(a) == content_hash(b)
    assert content_hash(a)[1] is True


def test_numbers_normalised() -> None:
    assert canonicalize("[1.0, 1, 1e2, 1.5, 0.1, -0, -0.0, 10E-1]") == "[1,1,100,1.5,0.1,0,0,1]"
    assert canonical_number("1.0") == canonical_number("1") == "1"
    assert canonical_number("2.50") == "2.5"
    assert canonical_number("-0") == "0"
    assert canonical_number("1e999").startswith("1E")
    assert canonical_number("abc") == "abc"


def test_duplicate_keys_last_wins() -> None:
    assert canonicalize('{"a":1,"a":2}') == '{"a":2}'


def test_invalid_json() -> None:
    assert canonicalize("{oops") is None
    assert canonicalize("NaN") is None
    assert canonicalize("[Infinity]") is None
    assert canonicalize("[" * 100000) is None
    digest, valid = content_hash("{oops")
    assert valid is False and digest == sha256_hex("raw:{oops")
    assert content_hash("{oops")[0] != content_hash("{oops ")[0]


def test_bom_and_sizes() -> None:
    assert strip_bom("﻿abc") == "abc" and strip_bom("abc") == "abc"
    assert canonicalize("﻿[1]") == "[1]"
    assert utf8_size("é😀") == 6


def test_preview() -> None:
    assert make_preview("  a\n\n b\t c ") == "a b c"
    assert len(make_preview("x" * 1000)) == 200
    assert make_preview("abcdef", 3) == "abc"


def test_prepare_content() -> None:
    assert prepare_content("﻿abc", 10) == ("abc", 3)
    with pytest.raises(PayloadTooLarge):
        prepare_content("abcd", 3)
    with pytest.raises(Unprocessable) as exc:
        prepare_content("a\x00", 10)
    assert exc.value.code == "invalid_content"


def test_auto_title() -> None:
    assert (
        auto_title('{"id":1,"name":"x","items":[],"more":1}', 2048) == "{id, name, items…} · 2 KB"
    )
    assert auto_title('{"a":1}', 7) == "{a} · 7 B"
    assert auto_title("[1,2,3]", 7) == "Array[3] · 7 B"
    assert auto_title("hello world", 11) == "hello world · 11 B"
    assert auto_title("x" * 100, 3 * 1024 * 1024) == "x" * 40 + " · 3.0 MB"
    assert (
        auto_title("{}", 2, "https://api.example.com/v1/data.json?x=1")
        == "api.example.com/data.json · 2 B"
    )
    assert auto_title("{}", 2, "https://api.example.com/") == "api.example.com · 2 B"
    assert auto_title("{bad", 4) == "{bad · 4 B"
