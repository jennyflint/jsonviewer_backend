from __future__ import annotations

import json
import random

import pytest

from app.domain.analysis.duplicates import analyze, check_text, load_document, resolve_path
from app.domain.analysis.positional_parser import parse
from app.domain.analysis.schemas import ByField, DuplicateOptions
from app.lib.errors import Unprocessable


def run(doc: object | str, **opts: object):  # type: ignore[no-untyped-def]
    text = doc if isinstance(doc, str) else json.dumps(doc)
    return analyze(text, DuplicateOptions(**opts))  # type: ignore[arg-type]


def test_duplicate_keys_with_positions() -> None:
    text = '{\n  "config": {\n    "timeout": 30,\n    "retries": 1,\n    "timeout": 60\n  },\n  "x": 1\n}'
    res = run(text)
    assert res.valid and len(res.duplicate_keys) == 1
    dk = res.duplicate_keys[0]
    assert (dk.object_path, dk.key) == ("$.config", "timeout")
    assert [(o.line, o.column, o.value_preview) for o in dk.occurrences] == [
        (3, 5, "30"),
        (5, 5, "60"),
    ]
    assert text[dk.occurrences[1].offset :].startswith('"timeout": 60')


def test_duplicate_keys_disabled_and_nested_paths() -> None:
    text = '{"a":[{"k":1,"k":2,"k":3}],"b c":{"z":1,"z":1}}'
    res = run(text)
    paths = {(d.object_path, d.key, len(d.occurrences)) for d in res.duplicate_keys}
    assert paths == {("$.a[0]", "k", 3), ('$["b c"]', "z", 2)}
    assert res.duplicate_keys[0].occurrences.__len__() == 3  # sorted by count desc
    assert run(text, keys=False).duplicate_keys == []


def test_effective_value_is_last_for_values_and_subtrees() -> None:
    res = run('{"a":"first","a":"second","b":"first"}')
    assert res.duplicate_values == []  # shadowed "first" is not part of the parsed data


def test_duplicate_values_by_type_and_number_canonicalisation() -> None:
    res = run(
        '{"a":1,"b":1.0,"c":1.50,"d":1.5,"e":"1","f":true,"g":true,"h":null,"i":null,"j":"x","k":"x","l":false}'
    )
    by = {(v.type, json.dumps(v.value)): v for v in res.duplicate_values}
    assert set(by) == {
        ("number", "1"),
        ("number", "1.5"),
        ("boolean", "true"),
        ("null", "null"),
        ("string", '"x"'),
    }
    one = by[("number", "1")]
    assert one.count == 2 and one.paths == ["$.a", "$.b"] and set(one.lexemes or []) == {"1", "1.0"}
    assert set(by[("number", "1.5")].lexemes or []) == {"1.50", "1.5"}
    assert by[("number", "1")].value == 1
    assert [v.type for v in res.duplicate_values if v.value == "1"] == []  # "1" string != 1 number


def test_value_filters() -> None:
    doc = {
        "a": "xx",
        "b": "xx",
        "c": "y",
        "d": "y",
        "e": 1,
        "f": 1,
        "g": None,
        "h": None,
        "i": True,
        "j": True,
    }
    assert {
        v.value for v in run(doc, min_string_length=2).duplicate_values if v.type == "string"
    } == {"xx"}
    assert {v.type for v in run(doc, value_types=["string"]).duplicate_values} == {"string"}
    assert {v.type for v in run(doc, value_types=["number", "null"]).duplicate_values} == {
        "number",
        "null",
    }
    assert run(doc, min_occurrences=3).duplicate_values == []
    assert run(doc, values=False).duplicate_values == []
    counts = run({"a": "x", "b": "x", "c": "x", "d": "y", "e": "y"}).duplicate_values
    assert [(v.value, v.count) for v in counts] == [("x", 3), ("y", 2)]  # count desc


def test_duplicate_subtrees() -> None:
    doc = {"items": [{"id": 1, "t": [1, 2]}, {"t": [1, 2], "id": 1}, {"id": 2, "t": [1, 2]}]}
    res = run(doc)
    top = next(s for s in res.duplicate_subtrees if s.kind == "object")
    assert top.kind == "object" and top.count == 2 and top.paths == ["$.items[0]", "$.items[1]"]
    assert top.size == 5 and len(top.hash) == 64
    # the [1,2] arrays occur 3 times, also outside the duplicated parents -> reported separately
    arr = next(s for s in res.duplicate_subtrees if s.kind == "array")
    assert arr.count == 3 and arr.preview == "[1,2]"


def test_nested_repeats_are_suppressed() -> None:
    doc = {"x": [{"inner": {"a": 1, "b": 2}, "n": 1}, {"inner": {"a": 1, "b": 2}, "n": 1}]}
    res = run(doc)
    assert [s.paths for s in res.duplicate_subtrees] == [
        ["$.x[0]", "$.x[1]"]
    ]  # child "inner" not repeated


def test_nested_repeat_kept_when_it_occurs_elsewhere() -> None:
    inner = {"a": 1, "b": 2}
    doc = {"x": [{"inner": inner, "n": 1}, {"inner": inner, "n": 1}], "extra": inner}
    res = run(doc)
    paths = [s.paths for s in res.duplicate_subtrees]
    assert ["$.x[0]", "$.x[1]"] in paths
    assert ["$.x[0].inner", "$.x[1].inner", "$.extra"] in paths


def test_repeat_inside_one_parent_kept() -> None:
    inner = {"a": 1, "b": 2}
    parent = {"p": inner, "q": inner}
    res = run({"one": parent, "two": parent})
    paths = [s.paths for s in res.duplicate_subtrees]
    assert ["$.one", "$.two"] in paths
    assert ["$.one.p", "$.one.q", "$.two.p", "$.two.q"] in paths


def test_subtree_min_size_and_toggle() -> None:
    doc = {"a": {"k": 1}, "b": {"k": 1}, "c": [], "d": []}
    assert [s.kind for s in run(doc).duplicate_subtrees] == ["object"]  # empties have size 1 < 2
    assert len(run(doc, min_subtree_size=1).duplicate_subtrees) == 2
    assert run(doc, min_subtree_size=5).duplicate_subtrees == []
    assert run(doc, subtrees=False).duplicate_subtrees == []


def test_subtree_hash_ignores_key_order_and_number_format() -> None:
    res = run('{"a":{"x":1,"y":[1.0]},"b":{"y":[1],"x":1.0}}')
    assert len(res.duplicate_subtrees) == 1 and res.duplicate_subtrees[0].count == 2


def test_by_field() -> None:
    doc = {
        "users": [
            {"email": "a@b.c", "n": 1},
            {"email": "x"},
            {"email": "a@b.c"},
            {"name": "no email"},
            {"email": 1},
            {"email": 1.0},
        ]
    }
    res = run(doc, by_field=ByField("$.users", "email"))
    bf = res.duplicates_by_field
    assert bf is not None and bf.missing == 1 and bf.array_path == "$.users"
    assert [(g.value, g.indices) for g in bf.groups] == [("a@b.c", [0, 2]), (1, [4, 5])]


def test_by_field_errors_and_path_syntax() -> None:
    for path in ["$.nope", "$.users[5]", "$.name", "users", "$..x", "$.users[", "$.n"]:
        with pytest.raises(Unprocessable) as exc:
            run({"users": [{"a": 1}], "name": "x", "n": [1]}, by_field=ByField(path, "a"))
        assert exc.value.code == "invalid_array_path", path
    nested = {"a": {"b c": [{"k": 1}, {"k": 1}]}, "arr": [[{"k": 2}, {"k": 2}]]}
    assert run(nested, by_field=ByField('$.a["b c"]', "k")).duplicates_by_field.groups[
        0
    ].indices == [0, 1]  # type: ignore[union-attr]
    assert run(nested, by_field=ByField("$.arr[0]", "k")).duplicates_by_field.groups[0].indices == [
        0,
        1,
    ]  # type: ignore[union-attr]
    assert resolve_path({"a": 1}, "$") == {"a": 1}
    res = run({"u": []}, by_field=ByField("$.u", "k"))
    assert res.duplicates_by_field.groups == []  # type: ignore[union-attr]


def test_by_field_container_values() -> None:
    res = run(
        {"u": [{"k": {"b": 1, "a": 2}}, {"k": {"a": 2, "b": 1}}]}, by_field=ByField("$.u", "k")
    )
    assert res.duplicates_by_field.groups[0].value == '{"a":2,"b":1}'  # type: ignore[union-attr]


def test_truncation() -> None:
    doc = {f"k{i}": f"v{i // 2}" for i in range(20)}  # 10 duplicated values
    res = run(doc, max_groups=3)
    assert len(res.duplicate_values) == 3 and res.truncated is True
    assert run(doc, max_groups=10).truncated is False
    many = "{" + ",".join(f'"k":{i}' for i in range(10)) + "}"
    assert run(many, max_groups=1).truncated is False  # a single dup key group


def test_invalid_document_reports_position() -> None:
    res = run('{"a": 1,\n "b": }')
    assert res.valid is False and res.parse_error is not None
    assert (res.parse_error.line, res.parse_error.column) == (2, 7)
    assert res.duplicate_keys == [] and res.stats.nodes == 0


def test_too_deep_raises() -> None:
    with pytest.raises(Unprocessable) as exc:
        run("[" * 513 + "]" * 513)
    assert exc.value.code == "nesting_too_deep"
    assert run("[" * 512 + "]" * 512).valid is True


def test_scalar_and_empty_documents() -> None:
    assert run("5").valid and run("[]").stats.nodes == 1 and run('"x"').duplicate_values == []
    assert run("[1,1]").duplicate_values[0].paths == ["$[0]", "$[1]"]


def test_check_text_and_special_numbers() -> None:
    assert check_text('{"a":1}') == (True, None)
    ok, err = check_text("NaN")
    assert ok is False and err is not None
    ok, err = check_text("[" * 600)
    assert ok is False and err is not None and err.message == "Nesting too deep"
    big = "1" * 5000
    ok, err = check_text(big)
    assert ok is False and err is not None and "too large" in err.message


def test_lone_surrogate_falls_back() -> None:
    res = run('{"a":{"s":"\\ud800"},"b":{"s":"\\ud800"}}')
    assert len(res.duplicate_subtrees) == 1


def test_node_count_and_depth_match_positional_parser() -> None:
    rng = random.Random(7)

    def gen(depth: int) -> object:
        r = rng.random()
        if depth > 4 or r < 0.3:
            return rng.choice([1, 2.5, "s,{[", None, True, "", 'q"uote'])
        if r < 0.65:
            return [gen(depth + 1) for _ in range(rng.randint(0, 4))]
        return {f"k{i},{{": gen(depth + 1) for i in range(rng.randint(0, 4))}

    for _ in range(200):
        text = json.dumps(gen(0), indent=rng.choice([None, 2]))
        loaded = load_document(text)
        ref = parse(text)
        assert loaded.valid and ref.valid
        assert (loaded.nodes, loaded.depth) == (ref.nodes, ref.depth), text


def test_performance_5mb_document() -> None:
    import time

    note = "x" * 40
    rows = ",".join(
        f'{{"id":{i},"name":"user number {i}","email":"u{i % 5000}@example.com",'
        f'"address":{{"city":"Kyiv","zip":"01001"}},"tags":["alpha","beta","gamma"],'
        f'"score":{i % 100}.5,"active":true,"note":"{note}"}}'
        for i in range(24000)
    )
    text = "[" + rows + "]"
    assert len(text.encode()) > 4_500_000
    started = time.perf_counter()
    res = analyze(text, DuplicateOptions())
    elapsed = time.perf_counter() - started
    assert res.valid and res.duplicate_values and res.duplicate_subtrees
    assert elapsed < 4.0, elapsed  # target is 2 s on a typical machine; allow slack for slow CI
