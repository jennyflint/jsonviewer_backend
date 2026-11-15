from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from litestar.middleware.csrf import generate_csrf_token
from litestar.testing import AsyncTestClient
from sqlalchemy import select, text

from app.db.models import Session, Share
from app.tasks.cleanup import CLEANUP_LOCK_ID, run_cleanup
from tests.conftest import SECRET, create_session, create_user

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------ rate limiting


@pytest.mark.parametrize(
    ("method", "url", "body", "limit"),
    [
        ("POST", "/api/fetch", {"url": "ftp://x"}, 20),
        ("POST", "/api/shares", {"content": "[]"}, 30),
        ("POST", "/api/analysis/validate", {"content": "[]"}, 60),
        ("GET", "/api/auth/providers", None, 30),
        ("GET", "/api/health/", None, None),  # health is not rate limited
    ],
)
async def test_rate_limits_per_group(
    new_client: Any, method: str, url: str, body: Any, limit: int | None
) -> None:
    async with new_client(rate_limit_multiplier=1) as c:
        if limit is None:
            for _ in range(50):
                assert (await c.request(method, url)).status_code == 200
            return
        for i in range(limit):
            resp = await c.request(method, url, json=body)
            assert resp.status_code != 429, i
        resp = await c.request(method, url, json=body)
        assert resp.status_code == 429
        assert int(resp.headers["retry-after"]) > 0
        assert resp.json()["error"]["code"] == "rate_limited"


async def test_share_limit_only_counts_post_and_groups_are_independent(new_client: Any) -> None:
    async with new_client(rate_limit_multiplier=1) as c:
        slug = (await c.post("/api/shares", json={"content": "[]"})).json()["slug"]
        for _ in range(60):
            assert (
                await c.get(f"/api/shares/{slug}")
            ).status_code == 200  # GETs fall under the default group
        for _ in range(29):
            await c.post("/api/shares", json={"content": "[]"})
        assert (await c.post("/api/shares", json={"content": "[]"})).status_code == 429
        assert (await c.post("/api/analysis/validate", json={"content": "[]"})).status_code == 200
        assert (await c.get(f"/api/shares/{slug}")).status_code == 200


async def test_default_group_limit(new_client: Any) -> None:
    async with new_client(rate_limit_multiplier=1) as c:
        for _ in range(300):
            assert (await c.get("/api/shares/none")).status_code == 404
        resp = await c.get("/api/shares/none")
        assert resp.status_code == 429 and "retry-after" in resp.headers


# ------------------------------------------------------------------ CSRF and origin


async def test_csrf_enforced_for_cookie_authenticated_unsafe_requests(
    new_client: Any, db: Any, user: Any
) -> None:
    raw = await create_session(db, user)
    token = generate_csrf_token(SECRET)
    async with new_client() as c:
        c.cookies.set("jv_session", raw)
        resp = await c.post("/api/history", json={"content": "[1]", "source": "manual"})
        assert resp.status_code == 403 and resp.json()["error"]["code"] == "csrf_failed"
        c.cookies.set("csrftoken", token)
        resp = await c.post("/api/history", json={"content": "[1]", "source": "manual"})
        assert resp.status_code == 403  # cookie alone is not enough
        resp = await c.post(
            "/api/history",
            json={"content": "[1]", "source": "manual"},
            headers={"X-CSRF-Token": generate_csrf_token(SECRET)},
        )
        assert resp.status_code == 403  # header must match the cookie
        resp = await c.post(
            "/api/history",
            json={"content": "[1]", "source": "manual"},
            headers={"X-CSRF-Token": token},
        )
        assert resp.status_code == 201
        for method, url in [
            ("PATCH", f"/api/history/{resp.json()['id']}"),
            ("DELETE", "/api/auth/sessions"),
        ]:
            assert (await c.request(method, url, json={"pinned": True})).status_code == 403
        assert (await c.post("/api/auth/logout")).status_code == 403
        assert (await c.get("/api/history")).status_code == 200  # safe methods are fine


async def test_anonymous_requests_skip_csrf(client: Any) -> None:
    assert (await client.post("/api/shares", json={"content": "[]"})).status_code == 201
    assert (await client.post("/api/analysis/validate", json={"content": "[]"})).status_code == 200


async def test_session_cookie_of_invalid_session_still_requires_csrf(client: Any) -> None:
    client.cookies.set("jv_session", "stale")
    resp = await client.post("/api/shares", json={"content": "[]"})
    assert resp.status_code == 403  # cookie present -> CSRF applies, even when the session is stale


async def test_origin_header_checked_on_unsafe_requests(client: Any) -> None:
    resp = await client.post(
        "/api/shares", json={"content": "[]"}, headers={"Origin": "https://evil.example"}
    )
    assert resp.status_code == 403 and resp.json()["error"]["code"] == "origin_not_allowed"
    for origin in ("http://localhost:3000", "http://localhost:5173", "http://testserver"):
        resp = await client.post("/api/shares", json={"content": "[]"}, headers={"Origin": origin})
        assert resp.status_code == 201, origin
    resp = await client.post("/api/shares", json={"content": "[]"}, headers={"Origin": "null"})
    assert resp.status_code == 403
    assert (
        await client.get("/api/health", headers={"Origin": "https://evil.example"})
    ).status_code == 200


# ------------------------------------------------------------------ CORS / headers / OpenAPI


async def test_cors(client: Any) -> None:
    resp = await client.options(
        "/api/shares",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )
    assert resp.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert resp.headers["access-control-allow-credentials"] == "true"
    resp = await client.options(
        "/api/shares",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in resp.headers
    resp = await client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert resp.headers["access-control-allow-origin"] == "http://localhost:3000"


async def test_security_headers_everywhere_and_no_store(auth_client: Any, client: Any) -> None:
    for resp in [
        await client.get("/api/health"),
        await client.get("/api/shares/zzz"),
        await client.get("/api/nope"),
        await client.post("/api/fetch", json={}),
        await client.put("/api/health"),
        await client.get("/other"),
    ]:
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    for url in ["/api/auth/me", "/api/auth/providers", "/api/history", "/api/auth/google/login"]:
        resp = await auth_client.get(url, follow_redirects=False)
        assert resp.headers["cache-control"] == "no-store", url
    assert "no-store" not in (await client.get("/api/health")).headers.get("cache-control", "")


async def test_openapi_docs(client: Any, new_client: Any) -> None:
    docs = await client.get("/api/docs")
    assert docs.status_code == 200 and "html" in docs.headers["content-type"]
    schema = (await client.get("/api/openapi.json")).json()
    assert schema["info"]["title"] == "JSON Viewer API"
    paths = set(schema["paths"])
    assert {
        "/api/health",
        "/api/fetch",
        "/api/shares",
        "/api/shares/{slug}",
        "/api/history",
        "/api/history/{entry_id}",
        "/api/analysis/duplicates",
        "/api/analysis/validate",
        "/api/auth/providers",
        "/api/auth/me",
        "/api/auth/logout",
        "/api/auth/{provider}/login",
        "/api/auth/{provider}/callback",
        "/api/auth/sessions",
        "/api/auth/account",
    } <= paths
    ops = [op for item in schema["paths"].values() for op in item.values()]
    assert all(op.get("summary") and op.get("tags") for op in ops)
    assert schema["paths"]["/api/shares"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]
    async with new_client(openapi_enabled=False) as c:
        assert (await c.get("/api/openapi.json")).status_code == 404
        assert (await c.get("/api/docs")).status_code == 404


# ------------------------------------------------------------------ errors and limits


async def test_unhandled_error_is_generic_500(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.domain.shares.service import ShareService

    async def boom(self: Any, slug: str, user: Any) -> None:
        raise RuntimeError("secret internals")

    monkeypatch.setattr(ShareService, "view", boom)
    resp = await client.get("/api/shares/abc")
    assert resp.status_code == 500
    assert resp.json() == {
        "error": {"code": "internal_error", "message": "Internal server error.", "details": None}
    }
    assert "secret" not in resp.text


async def test_validation_error_details(client: Any) -> None:
    resp = await client.post("/api/shares", json={"content": 5})
    body = resp.json()
    assert resp.status_code == 422 and body["error"]["code"] == "validation_error"
    assert body["error"]["details"]


async def test_request_body_limit(new_client: Any) -> None:
    async with new_client(max_fetch_bytes=1000) as c:
        resp = await c.post(
            "/api/analysis/validate",
            content=b'{"content":"' + b"x" * (1024 * 1024 + 2000) + b'"}',
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 413 and "error" in resp.json()


async def test_method_not_allowed_format(client: Any) -> None:
    resp = await client.put("/api/health")
    assert resp.status_code == 405 and resp.json()["error"]["code"] == "method_not_allowed"


async def test_health_reports_503_when_db_down(settings_factory: Any) -> None:
    from app.main import create_app

    app = create_app(settings_factory(database_url="postgresql+asyncpg://x:y@127.0.0.1:1/none"))
    async with AsyncTestClient(app=app, base_url="http://testserver") as c:
        resp = await c.get("/api/health")
        assert resp.status_code == 503 and resp.json()["db"] == "error"


async def test_logs_never_contain_document_content_or_tokens(
    client: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "TOP-SECRET-DOCUMENT-CONTENT"
    await client.post("/api/shares", json={"content": json.dumps({"k": secret})})
    await client.post("/api/analysis/duplicates", json={"content": json.dumps({"k": secret})})
    await client.get(
        "/api/auth/google/callback?code=SECRETCODE&state=SECRETSTATE", follow_redirects=False
    )
    out = capsys.readouterr().out
    assert (
        '"event": "request"' in out
        and secret not in out
        and "SECRETCODE" not in out
        and "SECRETSTATE" not in out
    )
    line = next(json.loads(x) for x in out.splitlines() if '"path": "/api/shares"' in x)
    assert {"method", "path", "status", "duration_ms", "request_id", "user_id"} <= set(line)


# ------------------------------------------------------------------ cleanup


async def test_cleanup_removes_expired_rows(engine: Any, db: Any, user: Any) -> None:
    now = datetime.now(UTC)

    def share(slug: str, expires: datetime | None) -> Share:
        return Share(slug=slug, kind="single", content="[]", size_bytes=2, expires_at=expires)  # type: ignore[arg-type]

    db.add_all(
        [
            share("expired1", now - timedelta(hours=1)),
            share("expired2", now - timedelta(days=3)),
            share("alive", now + timedelta(hours=1)),
            share("forever", None),
        ]
    )
    await db.commit()
    await create_session(db, user, expires_in=timedelta(days=1))
    await create_session(db, user, expires_in=timedelta(seconds=-10))
    result = await run_cleanup(engine)
    assert result == {"shares": 2, "sessions": 1}
    db.expire_all()
    assert {s.slug for s in (await db.execute(select(Share))).scalars()} == {"alive", "forever"}
    assert len((await db.execute(select(Session))).scalars().all()) == 1


async def test_cleanup_uses_advisory_lock(engine: Any, db: Any) -> None:
    async with engine.connect() as holder:
        await holder.execute(text("SELECT pg_advisory_lock(:id)"), {"id": CLEANUP_LOCK_ID})
        assert await run_cleanup(engine) is None  # another instance is cleaning
        await holder.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": CLEANUP_LOCK_ID})
        await holder.commit()
    assert await run_cleanup(engine) == {"shares": 0, "sessions": 0}


async def test_cleanup_loop_runs_and_cancels_cleanly(engine: Any, db: Any) -> None:
    from app.tasks.cleanup import cleanup_loop, stop_task

    db.add(
        Share(
            slug="gone",
            kind="single",
            content="[]",
            size_bytes=2,
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    )  # type: ignore[arg-type]
    await db.commit()
    task = asyncio.create_task(cleanup_loop(engine, 3600))
    for _ in range(50):
        await asyncio.sleep(0.1)
        db.expire_all()
        if not (await db.execute(select(Share))).first():
            break
    await stop_task(task)
    assert task.done() and not (await db.execute(select(Share))).first()


async def test_lifespan_starts_and_stops_cleanup_task(settings_factory: Any, db: Any) -> None:
    from app.main import create_app

    db.add(
        Share(
            slug="lifespan",
            kind="single",
            content="[]",
            size_bytes=2,
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    )  # type: ignore[arg-type]
    await db.commit()
    app = create_app(settings_factory(cleanup_interval_seconds=3600))
    async with AsyncTestClient(app=app, base_url="http://testserver"):
        for _ in range(50):
            await asyncio.sleep(0.1)
            db.expire_all()
            if not (await db.execute(select(Share))).first():
                break
    assert not (await db.execute(select(Share))).first()


async def test_cleanup_cli_command(database_url: str, db: Any, engine: Any) -> None:
    db.add(
        Share(
            slug="cli",
            kind="single",
            content="[]",
            size_bytes=2,
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    )  # type: ignore[arg-type]
    await db.commit()
    env = {
        **os.environ,
        "DATABASE_URL": database_url,
        "SECRET_KEY": SECRET,
        "PYTHONPATH": str(ROOT / "src"),
    }
    proc = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-m", "litestar", "--app", "app.main:app", "cleanup"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "'shares': 1" in proc.stdout
    db.expire_all()
    assert not (await db.execute(select(Share))).first()


async def test_user_helper_unused(db: Any) -> None:
    assert await create_user(db, None, "No email")


async def test_swagger_ui_available(client: Any) -> None:
    assert (await client.get("/api/docs/swagger")).status_code == 200
