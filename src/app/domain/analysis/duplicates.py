"""Duplicate detection (keys, values, subtrees, by-field).

Strategy: the C ``json`` scanner (with an ``object_pairs_hook`` that notices duplicate keys)
validates and loads the document quickly, using JSON.parse semantics (last duplicate wins).
The pure-Python positional parser is only used when its extra information is required:
syntax-error positions, and line/column of duplicate keys.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import accumulate
from typing import Any

import msgspec

from app.domain.analysis.positional_parser import MAX_DEPTH, parse, path_segment
from app.domain.analysis.schemas import (
    DuplicateKey,
    DuplicateOptions,
    DuplicatesByField,
    DuplicatesResponse,
    DuplicateSubtree,
    DuplicateValue,
    FieldGroup,
    KeyOccurrence,
    ParseErrorOut,
    Stats,
)
from app.lib.errors import Unprocessable

MAX_PATHS_PER_GROUP = 1000
PREVIEW_CHARS = 100

_STRIP_STRINGS = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_BRACKETS = re.compile(r"[\[\]{}]")
_EMPTY = re.compile(r"[\[{][ \t\r\n]*[\]}]")
_DELTA = {"[": 1, "{": 1, "]": -1, "}": -1}
_JSON_ENCODE = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode


def _enc_hook(obj: Any) -> Any:
    if isinstance(obj, int):
        return int(obj)
    if isinstance(obj, float):
        return float(obj)
    raise TypeError(type(obj))


_MSGSPEC_ENCODE = msgspec.json.Encoder(order="sorted", enc_hook=_enc_hook).encode


def _ENCODE(obj: Any) -> str:
    """Canonical (sorted, compact) JSON text used for hashing and previews."""
    return _JSON_ENCODE(obj)


class LexInt(int):
    """Integral number that remembers its original lexeme (``1.0`` == ``1``)."""

    lexeme: str


class LexFloat(float):
    lexeme: str


def _parse_float(s: str) -> Any:
    f = float(s)
    if f.is_integer() and abs(f) < 1e308:
        v = LexInt(int(f))
        v.lexeme = s
        return v
    if repr(f) == s:
        return f  # lexeme is recoverable from the value itself
    lf = LexFloat(f)
    lf.lexeme = s
    return lf


def _reject_constant(name: str) -> Any:
    raise ValueError(f"Invalid constant {name}")


@dataclass(slots=True)
class Loaded:
    data: Any = None
    valid: bool = False
    too_deep: bool = False
    has_dups: bool = False
    nodes: int = 0
    depth: int = 0
    error: ParseErrorOut | None = None


def load_document(text: str) -> Loaded:
    flag = [False]

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        d = dict(pairs)
        if len(d) != len(pairs):
            flag[0] = True
        return d

    try:
        data = json.loads(
            text, object_pairs_hook=hook, parse_float=_parse_float, parse_constant=_reject_constant
        )
    except (ValueError, RecursionError):
        res = parse(text)
        if res.too_deep:
            return Loaded(too_deep=True)
        if res.error is not None:
            return Loaded(error=ParseErrorOut(res.error.message, res.error.line, res.error.column))
        return Loaded(error=ParseErrorOut("Number literal is too large", 1, 1))

    stripped = _STRIP_STRINGS.sub('""', text)
    brackets = _BRACKETS.findall(stripped)
    depth = max(accumulate(map(_DELTA.__getitem__, brackets), initial=0))
    if depth > MAX_DEPTH:
        return Loaded(too_deep=True)
    opens = stripped.count("[") + stripped.count("{")
    empties = len(_EMPTY.findall(stripped))
    nodes = 1 + stripped.count(",") + (opens - empties)
    return Loaded(data=data, valid=True, has_dups=flag[0], nodes=nodes, depth=depth)


def check_text(text: str) -> tuple[bool, ParseErrorOut | None]:
    """Cheap validity check used by /fetch: (is_valid_json, parse_error)."""
    loaded = load_document(text)
    if loaded.too_deep:
        return False, ParseErrorOut("Nesting too deep", 1, 1)
    return loaded.valid, loaded.error


# ------------------------------------------------------------------------------ helpers


def _chain_path(chain: Any) -> str:
    parts: list[str] = []
    while chain is not None:
        chain, ref = chain
        parts.append(path_segment(ref))
    parts.append("$")
    parts.reverse()
    return "".join(parts)


def _plain(v: Any) -> Any:
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, int):
        return int(v)
    if isinstance(v, float):
        return float(v)
    return v


_PATH_TOKEN = re.compile(r'\.([A-Za-z_$][A-Za-z0-9_$]*)|\[(\d+)\]|\[("(?:[^"\\]|\\.)*")\]')


def resolve_path(data: Any, path: str) -> Any:
    if not path.startswith("$"):
        raise Unprocessable("array_path must start with '$'.", code="invalid_array_path")
    pos = 1
    cur = data
    while pos < len(path):
        m = _PATH_TOKEN.match(path, pos)
        if m is None:
            raise Unprocessable("Invalid array_path syntax.", code="invalid_array_path")
        pos = m.end()
        name, idx, quoted = m.groups()
        try:
            if idx is not None:
                cur = cur[int(idx)] if isinstance(cur, list) else _missing()
            else:
                key = name if name is not None else json.loads(quoted)
                cur = cur[key] if isinstance(cur, dict) else _missing()
        except (IndexError, KeyError):
            raise Unprocessable("array_path does not exist.", code="invalid_array_path") from None
    return cur


def _missing() -> Any:
    raise Unprocessable("array_path does not exist.", code="invalid_array_path")


def _tag(v: Any) -> tuple[Any, ...]:
    if isinstance(v, bool):
        return ("b", v)
    if v is None:
        return ("n",)
    if isinstance(v, str):
        return ("s", v)
    if isinstance(v, (int, float)):
        return ("#", v)
    return ("c", _ENCODE(v))


# ------------------------------------------------------------------------------ analysis


@dataclass(slots=True)
class _Walk:
    strs: dict[str, list[Any]] = field(default_factory=lambda: defaultdict(list))
    nums: dict[Any, list[Any]] = field(default_factory=lambda: defaultdict(list))
    num_lex: dict[Any, dict[str, int]] = field(default_factory=dict)
    bools: dict[bool, list[Any]] = field(default_factory=lambda: defaultdict(list))
    nulls: list[Any] = field(default_factory=list)
    conts: list[Any] = field(default_factory=list)
    chains: list[Any] = field(default_factory=list)
    parent: list[int] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)


def _walk(data: Any, want_values: bool, types: set[str], min_len: int) -> _Walk:
    w = _Walk()
    if not isinstance(data, (dict, list)):
        return w
    conts, chains, parent, sizes = w.conts, w.chains, w.parent, w.sizes
    conts.append(data)
    chains.append(None)
    parent.append(-1)
    sizes.append(1)
    t_str, t_num = "string" in types, "number" in types
    t_bool, t_null = "boolean" in types, "null" in types
    strs, nums, bools, nulls, num_lex = w.strs, w.nums, w.bools, w.nulls, w.num_lex
    # Depth-first, in document order, with an explicit stack (no recursion).
    stack: list[tuple[Any, Any, int]] = [
        (iter(data.items() if type(data) is dict else enumerate(data)), None, 0)
    ]
    while stack:
        it, chain, idx = stack[-1]
        for k, v in it:
            t = type(v)
            if t is dict or t is list:
                new_idx = len(conts)
                conts.append(v)
                new_chain = (chain, k)
                chains.append(new_chain)
                parent.append(idx)
                sizes.append(1)
                stack.append((iter(v.items() if t is dict else enumerate(v)), new_chain, new_idx))
                break
            sizes[idx] += 1
            if not want_values:
                continue
            if t is str:
                if t_str and len(v) >= min_len:
                    strs[v].append((chain, k))
            elif t is bool:
                if t_bool:
                    bools[v].append((chain, k))
            elif v is None:
                if t_null:
                    nulls.append((chain, k))
            elif t_num:
                nums[v].append((chain, k))
                lex = getattr(v, "lexeme", None)
                if lex is not None:
                    d = num_lex.setdefault(v, {})
                    d[lex] = d.get(lex, 0) + 1
        else:
            stack.pop()
    for j in range(len(conts) - 1, 0, -1):
        sizes[parent[j]] += sizes[j]
    return w


def _dup_keys(text: str, opts: DuplicateOptions) -> list[DuplicateKey]:
    res = parse(text)
    out: list[DuplicateKey] = []
    assert res.lines is not None
    for obj in res.dup_objects:
        assert obj.children is not None
        by_key: dict[str, list[Any]] = defaultdict(list)
        for child in obj.children:
            by_key[child.ref].append(child)  # type: ignore[index]
        obj_path = obj.path
        for key, members in by_key.items():
            if len(members) < 2:
                continue
            occ = []
            for m in members:
                line, col = res.lines.locate(m.kstart)
                raw = text[m.start : m.end]
                preview = raw if len(raw) <= 80 else raw[:80] + "…"
                occ.append(KeyOccurrence(line, col, m.kstart, preview))
            out.append(DuplicateKey(obj_path, key, occ))
    out.sort(key=lambda d: -len(d.occurrences))
    return out


def analyze(text: str, opts: DuplicateOptions) -> DuplicatesResponse:
    started = time.perf_counter()
    loaded = load_document(text)
    if loaded.too_deep:
        raise Unprocessable("JSON nesting is too deep.", code="nesting_too_deep")

    def elapsed() -> int:
        return int((time.perf_counter() - started) * 1000)

    if not loaded.valid:
        return DuplicatesResponse(
            False, loaded.error, Stats(0, 0, elapsed()), [], [], [], None, False
        )

    truncated = False
    cap = opts.max_groups

    keys: list[DuplicateKey] = []
    if opts.keys and loaded.has_dups:
        keys = _dup_keys(text, opts)
        if len(keys) > cap:
            keys, truncated = keys[:cap], True

    values: list[DuplicateValue] = []
    subtrees: list[DuplicateSubtree] = []
    by_field: DuplicatesByField | None = None

    if opts.values or opts.subtrees:
        walk = _walk(loaded.data, opts.values, set(opts.value_types), opts.min_string_length)
        if opts.values:
            values, cut = _value_groups(walk, opts, cap)
            truncated = truncated or cut
        if opts.subtrees:
            subtrees, cut = _subtree_groups(walk, opts, cap)
            truncated = truncated or cut

    if opts.by_field is not None:
        by_field, cut = _by_field(loaded.data, opts)
        truncated = truncated or cut

    return DuplicatesResponse(
        True,
        None,
        Stats(loaded.nodes, loaded.depth, elapsed()),
        keys,
        values,
        subtrees,
        by_field,
        truncated,
    )


def _value_groups(
    walk: _Walk, opts: DuplicateOptions, cap: int
) -> tuple[list[DuplicateValue], bool]:
    n = opts.min_occurrences
    groups: list[DuplicateValue] = []
    for s, occ in walk.strs.items():
        if len(occ) >= n:
            groups.append(DuplicateValue("string", s, len(occ), _paths(occ)))
    for num, occ in walk.nums.items():
        if len(occ) >= n:
            seen = walk.num_lex.get(num, {})
            lexemes = list(seen)
            if sum(seen.values()) < len(occ):  # some occurrences are plain int/float literals
                lexemes.append(repr(_plain(num)))
            groups.append(DuplicateValue("number", _plain(num), len(occ), _paths(occ), lexemes))
    for b, occ in walk.bools.items():
        if len(occ) >= n:
            groups.append(DuplicateValue("boolean", b, len(occ), _paths(occ)))
    if len(walk.nulls) >= n:
        groups.append(DuplicateValue("null", None, len(walk.nulls), _paths(walk.nulls)))
    groups.sort(key=lambda g: -g.count)
    return groups[:cap], len(groups) > cap


def _paths(occ: list[Any]) -> list[str]:
    return [_chain_path(c) for c in occ[:MAX_PATHS_PER_GROUP]]


def _subtree_groups(
    walk: _Walk, opts: DuplicateOptions, cap: int
) -> tuple[list[DuplicateSubtree], bool]:
    by_hash: dict[str, list[int]] = defaultdict(list)
    sha = hashlib.sha256
    min_size = opts.min_subtree_size
    sizes = walk.sizes
    candidates = [i for i in range(len(walk.conts)) if sizes[i] >= min_size]
    try:
        encoded = [_MSGSPEC_ENCODE(walk.conts[i]) for i in candidates]
    except (UnicodeEncodeError, TypeError, msgspec.EncodeError):
        encoded = [_ENCODE(walk.conts[i]).encode("utf-8", "surrogatepass") for i in candidates]
    for i, blob in zip(candidates, encoded, strict=True):
        by_hash[sha(blob).hexdigest()].append(i)

    n = opts.min_occurrences
    dup = {h: idx for h, idx in by_hash.items() if len(idx) >= n}
    is_dup: dict[int, str] = {i: h for h, idx in dup.items() for i in idx}

    groups: list[DuplicateSubtree] = []
    for h, idx in dup.items():
        positions: set[tuple[Any, ...]] = set()
        uncovered = 0
        for i in idx:
            anc, rel = _nearest_dup_ancestor(i, is_dup, walk)
            if anc is None:
                uncovered += 1
            else:
                positions.add((anc, rel))
        if uncovered + len(positions) < n:
            continue  # only repeats because a parent subtree is itself duplicated
        first = walk.conts[idx[0]]
        preview = _ENCODE(first)
        if len(preview) > PREVIEW_CHARS:
            preview = preview[:PREVIEW_CHARS] + "…"
        groups.append(
            DuplicateSubtree(
                hash=h,
                kind="object" if isinstance(first, dict) else "array",
                size=sizes[idx[0]],
                count=len(idx),
                preview=preview,
                paths=[_chain_path(walk.chains[i]) for i in idx[:MAX_PATHS_PER_GROUP]],
            )
        )
    groups.sort(key=lambda g: (-g.count, -g.size))
    return groups[:cap], len(groups) > cap


def _nearest_dup_ancestor(
    i: int, is_dup: dict[int, str], walk: _Walk
) -> tuple[str | None, tuple[Any, ...]]:
    rel: list[Any] = []
    cur = i
    while True:
        p = walk.parent[cur]
        if p < 0:
            return None, ()
        rel.append(walk.chains[cur][1])
        if p in is_dup:
            return is_dup[p], tuple(rel)
        cur = p


def _by_field(data: Any, opts: DuplicateOptions) -> tuple[DuplicatesByField, bool]:
    assert opts.by_field is not None
    arr = resolve_path(data, opts.by_field.array_path)
    if not isinstance(arr, list) or any(not isinstance(e, dict) for e in arr):
        raise Unprocessable(
            "array_path must resolve to an array of objects.", code="invalid_array_path"
        )
    fld = opts.by_field.field
    groups: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    sample: dict[tuple[Any, ...], Any] = {}
    missing = 0
    for idx, el in enumerate(arr):
        if fld not in el:
            missing += 1
            continue
        k = _tag(el[fld])
        groups[k].append(idx)
        sample.setdefault(k, el[fld])
    out = [
        FieldGroup(
            _plain(sample[k]) if not isinstance(sample[k], (dict, list)) else _ENCODE(sample[k]),
            idxs,
        )
        for k, idxs in groups.items()
        if len(idxs) >= opts.min_occurrences
    ]
    out.sort(key=lambda g: -len(g.indices))
    cut = len(out) > opts.max_groups
    return DuplicatesByField(opts.by_field.array_path, fld, out[: opts.max_groups], missing), cut
