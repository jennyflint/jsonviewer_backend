from __future__ import annotations

from typing import Any


async def test_health_ok(client: Any) -> None:
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok" and body["db"] == "ok" and body["version"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert resp.headers["x-request-id"]


async def test_request_id_propagated(client: Any) -> None:
    resp = await client.get("/api/health", headers={"X-Request-ID": "abc-123"})
    assert resp.headers["x-request-id"] == "abc-123"


async def test_unknown_route_uses_error_format(client: Any) -> None:
    resp = await client.get("/api/nope")
    assert resp.status_code == 404
    assert resp.json() == {
        "error": {"code": "not_found", "message": "Resource not found.", "details": None}
    }
