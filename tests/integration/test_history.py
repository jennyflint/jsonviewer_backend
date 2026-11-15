from __future__ import annotations

import uuid
from typing import Any

from tests.conftest import create_session, create_user, login


async def add(client: Any, content: str = '{"a": 1}', **kw: Any) -> Any:
    return await client.post("/api/history", json={"content": content, "source": "manual", **kw})


async def test_requires_auth(client: Any) -> None:
    for method, url in [
        ("GET", "/api/history"),
        ("POST", "/api/history"),
        ("GET", f"/api/history/{uuid.uuid4()}"),
    ]:
        resp = await client.request(method, url, json={} if method == "POST" else None)
        assert resp.status_code == 401, url
        assert resp.json()["error"]["code"] == "auth_required"
    assert resp.headers["cache-control"] == "no-store"


async def test_create_list_get_patch_delete(auth_client: Any) -> None:
    resp = await add(auth_client, '{"id": 1, "name": "x", "items": [], "extra": 1}')
    assert resp.status_code == 201
    entry = resp.json()
    assert entry["deduplicated"] is False and entry["is_valid_json"] is True
    assert entry["title"].startswith("{id, name, items…}") and "B" in entry["title"]
    eid = entry["id"]

    listing = (await auth_client.get("/api/history")).json()
    assert listing["total"] == 1 and "content" not in listing["items"][0]
    assert listing["items"][0]["preview"].startswith('{"id": 1')

    full = (await auth_client.get(f"/api/history/{eid}")).json()
    assert full["content"].startswith('{"id"')

    patched = await auth_client.patch(
        f"/api/history/{eid}", json={"title": "Renamed", "pinned": True}
    )
    assert patched.status_code == 200
    assert patched.json()["title"] == "Renamed" and patched.json()["pinned"] is True

    assert (await auth_client.delete(f"/api/history/{eid}")).status_code == 204
    assert (await auth_client.get(f"/api/history/{eid}")).status_code == 404


async def test_upsert_dedup_by_canonical_hash(auth_client: Any) -> None:
    first = await add(auth_client, '{"b": 1.0, "a": [1, 2]}', title="First")
    assert first.status_code == 201
    second = await add(
        auth_client, '{\n  "a": [1,2],\n  "b": 1\n}', source_url="https://x.test/d.json"
    )
    assert second.status_code == 200
    body = second.json()
    assert body["deduplicated"] is True and body["id"] == first.json()["id"]
    assert body["title"] == "First"  # untouched when no title is provided
    assert body["source_url"] == "https://x.test/d.json"
    renamed = await add(auth_client, '{"a":[1,2],"b":1}', title="New")
    assert renamed.json()["title"] == "New"
    assert (await auth_client.get("/api/history")).json()["total"] == 1


async def test_invalid_json_entry_and_titles(auth_client: Any) -> None:
    resp = await add(auth_client, "{oops")
    assert resp.json()["is_valid_json"] is False
    arr = await add(auth_client, "[1,2,3]")
    assert arr.json()["title"].startswith("Array[3]")
    url = await add(
        auth_client, '"x"', source="url", source_url="https://api.example.com/v1/data.json"
    )
    assert url.json()["title"].startswith("api.example.com/data.json")


async def test_quota_prunes_oldest_unpinned(
    make_app: Any, db: Any, user: Any, new_client: Any
) -> None:
    raw = await create_session(db, user)
    async with new_client(history_max_entries_per_user=3) as c:
        login(c, raw)
        ids = []
        for i in range(3):
            ids.append((await add(c, f"[{i}]")).json()["id"])
        await c.patch(f"/api/history/{ids[0]}", json={"pinned": True})
        await add(c, "[3]")
        listing = (await c.get("/api/history?limit=100")).json()
        remaining = {i["id"] for i in listing["items"]}
        assert len(remaining) == 3
        assert ids[0] in remaining  # pinned kept
        assert ids[1] not in remaining  # oldest unpinned pruned


async def test_search_filter_sort_pagination(auth_client: Any) -> None:
    await add(auth_client, '{"fruit": "banana"}', title="Fruits")
    await add(auth_client, '{"vehicle": "tractor"}', title="Machines")
    await add(auth_client, '{"color": "banana yellow"}', title="Colors", source="format")
    res = (await auth_client.get("/api/history?q=banana")).json()
    assert {i["title"] for i in res["items"]} == {"Fruits", "Colors"}
    res = (await auth_client.get("/api/history?q=machi")).json()  # trigram/ILIKE on title
    assert [i["title"] for i in res["items"]] == ["Machines"]
    res = (await auth_client.get("/api/history?source=format")).json()
    assert [i["title"] for i in res["items"]] == ["Colors"]
    res = (await auth_client.get("/api/history?sort=title&order=asc")).json()
    assert [i["title"] for i in res["items"]] == ["Colors", "Fruits", "Machines"]
    res = (await auth_client.get("/api/history?limit=2&offset=2&sort=title&order=asc")).json()
    assert [i["title"] for i in res["items"]] == ["Machines"] and res["total"] == 3
    assert (await auth_client.get("/api/history?sort=bogus")).status_code == 422
    first = (await auth_client.get("/api/history?limit=1")).json()["items"][0]["id"]
    await auth_client.patch(f"/api/history/{first}", json={"pinned": True})
    assert (await auth_client.get("/api/history?pinned=true")).json()["total"] == 1


async def test_isolation_between_users(auth_client: Any, db: Any, new_client: Any) -> None:
    eid = (await add(auth_client)).json()["id"]
    other = await create_user(db, "o@example.com")
    raw = await create_session(db, other)
    async with new_client() as oc:
        login(oc, raw)
        assert (await oc.get(f"/api/history/{eid}")).status_code == 404
        assert (await oc.patch(f"/api/history/{eid}", json={"pinned": True})).status_code == 404
        assert (await oc.delete(f"/api/history/{eid}")).status_code == 404
        assert (await oc.get("/api/history")).json()["total"] == 0
        assert (await add(oc)).status_code == 201  # same content, separate user
    assert (await auth_client.get(f"/api/history/{eid}")).status_code == 200


async def test_clear_requires_confirmation(auth_client: Any) -> None:
    await add(auth_client)
    resp = await auth_client.request("DELETE", "/api/history", json={"confirm": False})
    assert resp.status_code == 422
    resp = await auth_client.request("DELETE", "/api/history", json={"confirm": True})
    assert resp.status_code == 204
    assert (await auth_client.get("/api/history")).json()["total"] == 0


async def test_too_large_and_nul(auth_client: Any) -> None:
    assert (await add(auth_client, "a\x00")).json()["error"]["code"] == "invalid_content"
