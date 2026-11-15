from __future__ import annotations

import json
from typing import Any


async def dup(client: Any, content: str, **options: Any) -> Any:
    return await client.post(
        "/api/analysis/duplicates", json={"content": content, "options": options}
    )


async def test_duplicates_endpoint_full_shape(client: Any) -> None:
    doc = (
        '{\n  "users": [\n    {"email": "a@b.c", "id": 1},\n    {"email": "a@b.c", "id": 2},\n'
        '    {"email": "z", "id": 1}\n  ],\n  "cfg": {"t": 1, "t": 2}\n}'
    )
    resp = await dup(client, doc, by_field={"array_path": "$.users", "field": "email"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True and body["parse_error"] is None and body["truncated"] is False
    assert set(body["stats"]) == {"nodes", "depth", "elapsed_ms"}
    assert body["duplicate_keys"][0]["object_path"] == "$.cfg"
    assert body["duplicate_keys"][0]["occurrences"][0] == {
        "line": 7,
        "column": 11,
        "offset": body["duplicate_keys"][0]["occurrences"][0]["offset"],
        "value_preview": "1",
    }
    assert any(v["value"] == "a@b.c" and v["count"] == 2 for v in body["duplicate_values"])
    assert body["duplicates_by_field"] == {
        "array_path": "$.users",
        "field": "email",
        "groups": [{"value": "a@b.c", "indices": [0, 1]}],
        "missing": 0,
    }
    assert isinstance(body["duplicate_subtrees"], list)


async def test_default_options_and_invalid_json(client: Any) -> None:
    resp = await client.post("/api/analysis/duplicates", json={"content": '{"a": 1, "a": 2'})
    body = resp.json()
    assert resp.status_code == 200 and body["valid"] is False
    assert body["parse_error"]["message"] and body["parse_error"]["line"] == 1
    assert body["duplicate_keys"] == [] and body["duplicates_by_field"] is None


async def test_errors(client: Any, new_client: Any) -> None:
    resp = await dup(client, '{"a": []}', by_field={"array_path": "$.a.b", "field": "x"})
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "invalid_array_path"
    resp = await dup(client, "[" * 600 + "]" * 600)
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "nesting_too_deep"
    assert (await dup(client, "[]", min_occurrences=1)).status_code == 422
    assert (await dup(client, "[]", max_groups=0)).status_code == 422
    assert (await dup(client, "[]", value_types=["bogus"])).status_code == 422
    assert (await client.post("/api/analysis/duplicates", json={})).status_code == 422
    resp = await dup(client, "a\x00b")
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "invalid_content"
    async with new_client(max_document_bytes=50) as c:
        resp = await dup(c, "[" + "1," * 100 + "1]")
        assert resp.status_code == 413 and resp.json()["error"]["code"] == "document_too_large"


async def test_timeout_returns_504(client: Any, monkeypatch: Any) -> None:
    import time

    from app.domain.analysis import controller

    monkeypatch.setattr(controller, "ANALYSIS_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(controller, "analyze", lambda text, opts: time.sleep(1))
    resp = await dup(client, "[]")
    assert resp.status_code == 504 and resp.json()["error"]["code"] == "analysis_timeout"


async def test_validate_endpoint(client: Any) -> None:
    ok = (
        await client.post("/api/analysis/validate", json={"content": '{"a": [1, 2, {"b": null}]}'})
    ).json()
    assert ok == {
        "valid": True,
        "parse_error": None,
        "stats": {"nodes": 6, "depth": 3, "size_bytes": 26},
        "has_duplicate_keys": False,
    }
    dups = (await client.post("/api/analysis/validate", json={"content": '{"a":1,"a":2}'})).json()
    assert dups["valid"] is True and dups["has_duplicate_keys"] is True
    bad = (await client.post("/api/analysis/validate", json={"content": "[1,,]"})).json()
    assert bad["valid"] is False and bad["parse_error"] == {
        "message": "Unexpected token ','",
        "line": 1,
        "column": 4,
    }
    deep = await client.post("/api/analysis/validate", json={"content": "[" * 600})
    assert deep.status_code == 422 and deep.json()["error"]["code"] == "nesting_too_deep"
    assert (await client.post("/api/analysis/validate", json={})).status_code == 422


async def test_validate_unicode_size(client: Any) -> None:
    body = (
        await client.post(
            "/api/analysis/validate", json={"content": json.dumps({"k": "é😀"}, ensure_ascii=False)}
        )
    ).json()
    assert body["stats"]["size_bytes"] == len('{"k": "é😀"}'.encode())
