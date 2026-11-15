from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlparse

from app.lib.errors import PayloadTooLarge, Unprocessable

BOM = "﻿"
_WS = re.compile(r"\s+")


def strip_bom(text: str) -> str:
    return text[1:] if text.startswith(BOM) else text


def utf8_size(text: str) -> int:
    return len(text.encode("utf-8", errors="surrogatepass"))


def make_preview(text: str, n: int = 200) -> str:
    return _WS.sub(" ", text[: n * 4]).strip()[:n]


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="surrogatepass")).hexdigest()


def prepare_content(text: str, max_bytes: int, *, field: str = "content") -> tuple[str, int]:
    """Strip BOM, reject NUL bytes and enforce the document size limit."""
    text = strip_bom(text)
    if "\x00" in text:
        raise Unprocessable(
            "Content contains NUL bytes.", code="invalid_content", details={"field": field}
        )
    size = utf8_size(text)
    if size > max_bytes:
        raise PayloadTooLarge(f"Document exceeds {max_bytes} bytes.", code="document_too_large")
    return text, size


def canonical_number(lexeme: str) -> str:
    """Canonical string of a JSON number: ``1.0`` and ``1`` compare equal."""
    try:
        d = Decimal(lexeme)
    except InvalidOperation:
        return lexeme
    if d == 0:
        return "0"
    if d.adjusted() > 400 or d.adjusted() < -400:
        return format(d.normalize(), "E")
    if d == d.to_integral_value():
        return str(int(d))
    return repr(float(d))


def _reject_constant(name: str) -> Any:
    raise ValueError(f"Invalid constant {name}")


class _Num:
    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def _serialize(value: Any, out: list[str]) -> None:
    if isinstance(value, dict):
        out.append("{")
        first = True
        for key in sorted(value):
            if not first:
                out.append(",")
            first = False
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    elif isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, _Num):
        out.append(value.text)
    else:
        out.append(json.dumps(value, ensure_ascii=False))


def canonicalize(text: str) -> str | None:
    """Sorted keys, no whitespace, normalized numbers; last duplicate key wins. None if invalid."""
    try:
        data = json.loads(
            strip_bom(text),
            parse_float=lambda s: _Num(canonical_number(s)),
            parse_int=lambda s: _Num(canonical_number(s)),
            parse_constant=_reject_constant,
        )
        out: list[str] = []
        _serialize(data, out)
        return "".join(out)
    except (ValueError, RecursionError):
        return None


def content_hash(text: str) -> tuple[str, bool]:
    """Return (hash, is_valid_json)."""
    canon = canonicalize(text)
    if canon is None:
        return sha256_hex("raw:" + text), False
    return sha256_hex(canon), True


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{round(n / 1024)} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def auto_title(content: str, size_bytes: int, source_url: str | None = None) -> str:
    suffix = f" · {_human_size(size_bytes)}"
    if source_url:
        parsed = urlparse(source_url)
        base = (parsed.path.rstrip("/").rsplit("/", 1)[-1]) if parsed.path else ""
        host = parsed.hostname or source_url
        return (f"{host}/{base}" if base else host)[:150] + suffix
    try:
        root = json.loads(strip_bom(content))
    except (ValueError, RecursionError):
        root = None
        valid = False
    else:
        valid = True
    if valid and isinstance(root, dict):
        keys = list(root.keys())
        inner = ", ".join(keys[:3]) + ("…" if len(keys) > 3 else "")
        return "{" + inner + "}" + suffix
    if valid and isinstance(root, list):
        return f"Array[{len(root)}]" + suffix
    return make_preview(content, 40) + suffix
