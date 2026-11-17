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


# ----------------------------------------------------------- password / burn-after-read / comments


async def test_password_protected_share(client: Any) -> None:
    created = (await create(client, password="s3cret!")).json()
    slug = created["slug"]
    meta = (await client.get(f"/api/shares/{slug}/meta")).json()
    assert meta["password_protected"] is True and meta["burn_after_read"] is False
    assert "content" not in meta
    locked = await client.get(f"/api/shares/{slug}")
    assert locked.status_code == 403 and locked.json()["error"]["code"] == "share_locked"
    no_pw = await client.post(f"/api/shares/{slug}/open", json={})
    assert no_pw.status_code == 403 and no_pw.json()["error"]["code"] == "password_required"
    wrong = await client.post(f"/api/shares/{slug}/open", json={"password": "nope-nope"})
    assert wrong.status_code == 403 and wrong.json()["error"]["code"] == "invalid_password"
    ok = await client.post(f"/api/shares/{slug}/open", json={"password": "s3cret!"})
    assert ok.status_code == 200
    assert ok.json()["content"] == '{"a": 1}' and ok.json()["password_protected"] is True


async def test_password_is_hashed_and_validated(client: Any, db: Any) -> None:
    short = await create(client, password="abc")
    assert short.status_code == 422
    await create(client, password="longenough")
    row = (await db.execute(select(Share))).scalar_one()
    assert row.password_hash and row.password_hash.startswith("scrypt$")
    assert "longenough" not in row.password_hash


async def test_burn_after_read_is_destroyed_after_one_open(client: Any, db: Any) -> None:
    slug = (await create(client, burn_after_read=True)).json()["slug"]
    # describing it (e.g. a link preview bot) does not burn it
    meta = (await client.get(f"/api/shares/{slug}/meta")).json()
    assert meta["burn_after_read"] is True
    assert (await client.get(f"/api/shares/{slug}")).status_code == 403
    assert (await db.execute(select(Share))).scalar_one()
    first = await client.post(f"/api/shares/{slug}/open", json={})
    assert first.status_code == 200 and first.json()["content"] == '{"a": 1}'
    second = await client.post(f"/api/shares/{slug}/open", json={})
    assert second.status_code == 404
    assert (await client.get(f"/api/shares/{slug}/meta")).status_code == 404


async def test_burn_with_wrong_password_is_not_burned(client: Any) -> None:
    slug = (await create(client, burn_after_read=True, password="correct-horse")).json()["slug"]
    bad = await client.post(f"/api/shares/{slug}/open", json={"password": "wrong-horse"})
    assert bad.status_code == 403
    good = await client.post(f"/api/shares/{slug}/open", json={"password": "correct-horse"})
    assert good.status_code == 200


async def test_open_works_for_normal_shares_too(client: Any) -> None:
    slug = (await create(client)).json()["slug"]
    r = await client.post(f"/api/shares/{slug}/open", json={})
    assert r.status_code == 200 and r.json()["view_count"] == 1
    assert (await client.get(f"/api/shares/{slug}")).status_code == 200


async def test_comments_lifecycle(client: Any) -> None:
    created = (await create(client, comments_enabled=True)).json()
    slug, token = created["slug"], created["delete_token"]
    assert (await client.get(f"/api/shares/{slug}/meta")).json()["comments_enabled"] is True
    assert (await client.get(f"/api/shares/{slug}/comments")).json() == []
    c = await client.post(
        f"/api/shares/{slug}/comments",
        json={"text": "Why 1?", "author": "Ann", "path": "$.a"},
    )
    assert c.status_code == 201
    cid = c.json()["id"]
    assert c.json()["path"] == "$.a" and c.json()["author"] == "Ann"
    listed = (await client.get(f"/api/shares/{slug}/comments")).json()
    assert [x["text"] for x in listed] == ["Why 1?"]
    # strangers cannot delete, the delete-token holder can
    assert (await client.delete(f"/api/shares/{slug}/comments/{cid}")).status_code == 403
    ok = await client.delete(
        f"/api/shares/{slug}/comments/{cid}", headers={"X-Delete-Token": token}
    )
    assert ok.status_code == 204
    assert (await client.get(f"/api/shares/{slug}/comments")).json() == []


async def test_comments_disabled_by_default_and_validated(client: Any) -> None:
    slug = (await create(client)).json()["slug"]
    r = await client.post(f"/api/shares/{slug}/comments", json={"text": "x", "author": "a"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "comments_disabled"
    on = (await create(client, comments_enabled=True)).json()["slug"]
    assert (
        await client.post(f"/api/shares/{on}/comments", json={"text": "", "author": "a"})
    ).status_code == 422
    big = await client.post(f"/api/shares/{on}/comments", json={"text": "x" * 2001, "author": "a"})
    assert big.status_code == 422


async def test_comments_respect_the_password(client: Any) -> None:
    slug = (await create(client, comments_enabled=True, password="hunter22")).json()["slug"]
    body = {"text": "hi", "author": "a"}
    assert (await client.get(f"/api/shares/{slug}/comments")).status_code == 403
    assert (await client.post(f"/api/shares/{slug}/comments", json=body)).status_code == 403
    h = {"X-Share-Password": "hunter22"}
    assert (
        await client.post(f"/api/shares/{slug}/comments", json=body, headers=h)
    ).status_code == 201
    assert len((await client.get(f"/api/shares/{slug}/comments", headers=h)).json()) == 1


async def test_comments_are_removed_with_the_share(client: Any, db: Any) -> None:
    from app.db.models import ShareComment

    created = (await create(client, comments_enabled=True)).json()
    slug = created["slug"]
    await client.post(f"/api/shares/{slug}/comments", json={"text": "x", "author": "a"})
    assert (await db.execute(select(ShareComment))).scalars().all()
    d = await client.delete(
        f"/api/shares/{slug}", headers={"X-Delete-Token": created["delete_token"]}
    )
    assert d.status_code == 204
    assert not (await db.execute(select(ShareComment))).scalars().all()
