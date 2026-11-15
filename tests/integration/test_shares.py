from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update

from app.db.models import HistoryEntry, Share
from app.lib.security import token_hash


async def create(client: Any, **kw: Any) -> Any:
    body = {"content": '{"a": 1}', **kw}
    return await client.post("/api/shares", json=body)


async def test_anonymous_create_and_read(client: Any, db: Any) -> None:
    resp = await create(client, title="hello")
    assert resp.status_code == 201
    data = resp.json()
    assert len(data["slug"]) == 12
    assert data["url"] == f"http://localhost:3000/s/{data['slug']}"
    assert data["delete_token"]
    assert data["expires_at"]  # default 30d
    row = (await db.execute(select(Share))).scalar_one()
    assert row.delete_token_hash == token_hash(data["delete_token"])
    assert row.owner_id is None

    got = await client.get(f"/api/shares/{data['slug']}")
    assert got.status_code == 200
    body = got.json()
    assert body["content"] == '{"a": 1}' and body["title"] == "hello"
    assert body["is_owner"] is False and body["view_count"] == 1
    got = await client.get(f"/api/shares/{data['slug']}")
    assert got.json()["view_count"] == 2


async def test_broken_json_and_exact_content_preserved(client: Any) -> None:
    raw = '{"a": 1, "a": 2,  }\n'
    slug = (await create(client, content=raw)).json()["slug"]
    assert (await client.get(f"/api/shares/{slug}")).json()["content"] == raw


async def test_bom_stripped_nul_rejected(client: Any) -> None:
    slug = (await create(client, content="﻿[1]")).json()["slug"]
    assert (await client.get(f"/api/shares/{slug}")).json()["content"] == "[1]"
    resp = await create(client, content="a\x00b")
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "invalid_content"


async def test_never_requires_auth(client: Any, auth_client: Any) -> None:
    resp = await create(client, expires_in="never")
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "never_requires_auth"
    ok = await create(auth_client, expires_in="never")
    assert ok.status_code == 201 and ok.json()["expires_at"] is None
    assert ok.json()["delete_token"] is None


async def test_invalid_expires_in(client: Any) -> None:
    resp = await create(client, expires_in="2d")
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "validation_error"


async def test_compare_requires_right(client: Any) -> None:
    resp = await create(client, kind="compare")
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "content_right_required"
    ok = await create(client, kind="compare", content_right="[2]")
    slug = ok.json()["slug"]
    body = (await client.get(f"/api/shares/{slug}")).json()
    assert body["kind"] == "compare" and body["content_right"] == "[2]"
    assert body["size_bytes"] == len('{"a": 1}') + 3


async def test_too_large(make_app: Any, new_client: Any) -> None:
    async with new_client(max_document_bytes=100) as c:
        resp = await create(c, content="x" * 101)
        assert resp.status_code == 413
        assert resp.json()["error"]["code"] == "document_too_large"


async def test_expiry_returns_404(client: Any, db: Any) -> None:
    slug = (await create(client, expires_in="1h")).json()["slug"]
    await db.execute(update(Share).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    await db.commit()
    resp = await client.get(f"/api/shares/{slug}")
    assert resp.status_code == 404 and resp.json()["error"]["code"] == "share_not_found"
    missing = await client.get("/api/shares/doesnotexist")
    assert missing.json() == resp.json()


async def test_delete_with_token(client: Any) -> None:
    data = (await create(client)).json()
    url = f"/api/shares/{data['slug']}"
    assert (await client.delete(url)).status_code == 403
    assert (await client.delete(url, headers={"X-Delete-Token": "wrong"})).status_code == 403
    assert (
        await client.delete(url, headers={"X-Delete-Token": data["delete_token"]})
    ).status_code == 204
    assert (
        await client.delete(url, headers={"X-Delete-Token": data["delete_token"]})
    ).status_code == 404
    assert (await client.get(url)).status_code == 404


async def test_owner_delete_and_forbidden_for_others(
    auth_client: Any, new_client: Any, db: Any
) -> None:
    from tests.conftest import create_session, create_user, login

    data = (await create(auth_client)).json()
    url = f"/api/shares/{data['slug']}"
    assert (await auth_client.get(url)).json()["is_owner"] is True

    other = await create_user(db, "other@example.com")
    raw = await create_session(db, other)
    async with new_client() as oc:
        login(oc, raw)
        assert (await oc.delete(url)).status_code == 403
    assert (await auth_client.delete(url)).status_code == 204


async def test_list_requires_auth_and_paginates(client: Any, auth_client: Any) -> None:
    assert (await client.get("/api/shares")).status_code == 401
    for i in range(3):
        await create(auth_client, content=f'{{"n": {i}}}')
    await create(client)  # anonymous: not listed
    resp = await auth_client.get("/api/shares?limit=2&offset=0")
    body = resp.json()
    assert body["total"] == 3 and len(body["items"]) == 2
    assert "content" not in body["items"][0] and body["items"][0]["preview"]
    resp = await auth_client.get("/api/shares?limit=2&offset=2")
    assert len(resp.json()["items"]) == 1
    assert (await auth_client.get("/api/shares?limit=1000")).status_code == 422


async def test_save_to_history(auth_client: Any, db: Any) -> None:
    resp = await create(auth_client, save_to_history=True, content='{"id": 1, "name": "x"}')
    assert resp.status_code == 201
    entry = (await db.execute(select(HistoryEntry))).scalar_one()
    assert entry.source.value == "share" and entry.share_id is not None
    await create(
        auth_client,
        save_to_history=True,
        kind="compare",
        content='{"id":1,"name":"x"}',
        content_right="[]",
    )
    await db.rollback()
    entries = (await db.execute(select(HistoryEntry))).scalars().all()
    assert len(entries) == 1 and entries[0].source.value == "compare"  # dedup by content hash


async def test_anonymous_ignores_save_to_history(client: Any, db: Any) -> None:
    assert (await create(client, save_to_history=True)).status_code == 201
    assert (await db.execute(select(HistoryEntry))).first() is None
