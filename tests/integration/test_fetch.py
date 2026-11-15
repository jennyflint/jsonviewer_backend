from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from app.domain.fetch import ssrf

DNS = {
    "example.com": ["93.184.216.34"],
    "cdn.example.com": ["93.184.216.35"],
    "evil.example": ["10.0.0.5"],
    "mixed.example": ["93.184.216.34", "127.0.0.1"],
    "rebind.example": ["169.254.169.254"],
}


@pytest.fixture(autouse=True)
def stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(host: str, port: int) -> list[str]:
        if host not in DNS:
            raise ssrf.DnsResolutionFailed()
        return DNS[host]

    monkeypatch.setattr(ssrf, "resolve_host", fake)


async def fetch(client: Any, url: str) -> Any:
    return await client.post("/api/fetch", json={"url": url})


@respx.mock
async def test_success_returns_raw_text(client: Any) -> None:
    raw = '{"a": 1,\n  "a": 2}'
    respx.get("https://example.com/data.json").mock(
        return_value=httpx.Response(200, text=raw, headers={"content-type": "application/json"})
    )
    resp = await fetch(client, "https://example.com/data.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["content"] == raw  # duplicate keys / formatting preserved
    assert body["is_valid_json"] is True and body["parse_error"] is None
    assert body["final_url"] == "https://example.com/data.json" and body["status_code"] == 200
    assert body["content_type"] == "application/json" and body["size_bytes"] == len(raw)
    request = respx.calls.last.request
    assert request.headers["user-agent"] == "JSONViewer/1.0"
    assert request.headers["accept"] == "application/json, */*;q=0.8"
    assert request.headers["host"] == "example.com"
    assert "cookie" not in request.headers and "authorization" not in request.headers


@respx.mock
async def test_client_headers_are_not_forwarded(auth_client: Any) -> None:
    respx.get("https://example.com/x").mock(return_value=httpx.Response(200, text="[]"))
    resp = await auth_client.post(
        "/api/fetch",
        json={"url": "https://example.com/x"},
        headers={"Authorization": "Bearer secret", "X-Foo": "bar"},
    )
    assert resp.status_code == 200
    sent = respx.calls.last.request.headers
    assert "authorization" not in sent and "x-foo" not in sent and "cookie" not in sent


@respx.mock
async def test_invalid_json_passthrough(client: Any) -> None:
    respx.get("https://example.com/bad").mock(
        return_value=httpx.Response(200, text='{"a": 1,\n "b": }')
    )
    body = (await fetch(client, "https://example.com/bad")).json()
    assert body["is_valid_json"] is False and body["content"] == '{"a": 1,\n "b": }'
    assert body["parse_error"] == {"message": "Unexpected token '}'", "line": 2, "column": 7}


@respx.mock
async def test_charset_and_bom(client: Any) -> None:
    payload = "﻿" + '{"name": "Привіт"}'
    respx.get("https://example.com/utf8").mock(
        return_value=httpx.Response(200, content=payload.encode("utf-8"))
    )
    body = (await fetch(client, "https://example.com/utf8")).json()
    assert body["content"] == '{"name": "Привіт"}' and body["is_valid_json"] is True
    respx.get("https://example.com/latin").mock(
        return_value=httpx.Response(
            200,
            content='{"n": "é"}'.encode("latin-1"),
            headers={"content-type": "application/json; charset=latin-1"},
        )
    )
    assert (await fetch(client, "https://example.com/latin")).json()["content"] == '{"n": "é"}'
    respx.get("https://example.com/weird").mock(
        return_value=httpx.Response(
            200, content=b"[1]", headers={"content-type": "text/plain; charset=nope"}
        )
    )
    assert (await fetch(client, "https://example.com/weird")).json()["content"] == "[1]"


@respx.mock
async def test_redirect_followed_and_final_url(client: Any) -> None:
    respx.get("https://example.com/a").mock(
        return_value=httpx.Response(302, headers={"location": "https://cdn.example.com/b"})
    )
    respx.get("https://cdn.example.com/b").mock(
        return_value=httpx.Response(301, headers={"location": "/c.json"})
    )
    respx.get("https://cdn.example.com/c.json").mock(return_value=httpx.Response(200, text="[1]"))
    body = (await fetch(client, "https://example.com/a")).json()
    assert (
        body["final_url"] == "https://cdn.example.com/c.json"
        and body["url"] == "https://example.com/a"
    )


@respx.mock
async def test_too_many_redirects(client: Any) -> None:
    respx.get("https://example.com/loop").mock(
        return_value=httpx.Response(302, headers={"location": "https://example.com/loop"})
    )
    resp = await fetch(client, "https://example.com/loop")
    assert resp.status_code == 502 and resp.json()["error"]["code"] == "too_many_redirects"
    assert len(respx.calls) == 4  # initial request + FETCH_MAX_REDIRECTS(3)


@pytest.mark.parametrize(
    "location",
    [
        "http://evil.example/x",  # resolves to a private IP
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://2130706433/",
        "http://localhost/",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "http://user:pw@example.com/",
        "http://rebind.example/",
        "http://example.com:22/",
    ],
)
@respx.mock
async def test_redirect_to_blocked_destination_is_rejected(client: Any, location: str) -> None:
    respx.get("https://example.com/start").mock(
        return_value=httpx.Response(302, headers={"location": location})
    )
    resp = await fetch(client, "https://example.com/start")
    assert resp.status_code == 422, resp.json()
    assert resp.json()["error"]["code"] in {"blocked_destination", "invalid_url"}
    assert len(respx.calls) == 1  # the blocked hop was never requested


@pytest.mark.parametrize(
    ("url", "status", "code"),
    [
        ("http://127.0.0.1/", 422, "blocked_destination"),
        ("http://localhost:8000/api/health", 422, "blocked_destination"),
        ("http://0177.0.0.1/", 422, "blocked_destination"),
        ("http://2130706433/", 422, "blocked_destination"),
        ("http://[::ffff:7f00:1]/", 422, "blocked_destination"),
        ("http://169.254.169.254/", 422, "blocked_destination"),
        ("http://evil.example/", 422, "blocked_destination"),
        ("http://mixed.example/", 422, "blocked_destination"),
        ("http://10.1.1.1:8080/", 422, "blocked_destination"),
        ("ftp://example.com/", 422, "invalid_url"),
        ("not a url", 422, "invalid_url"),
        ("http://user:pass@example.com/", 422, "invalid_url"),
        ("https://example.com:22/", 422, "invalid_url"),
        ("https://nonexistent.example/", 502, "dns_resolution_failed"),
    ],
)
async def test_blocked_and_invalid_urls(client: Any, url: str, status: int, code: str) -> None:
    resp = await fetch(client, url)
    assert resp.status_code == status and resp.json()["error"]["code"] == code
    text = resp.text
    assert "10.0.0.5" not in text and "169.254" not in text  # resolved IPs are never revealed


@respx.mock
async def test_upstream_errors(client: Any) -> None:
    respx.get("https://example.com/404").mock(return_value=httpx.Response(404, text="nope"))
    resp = await fetch(client, "https://example.com/404")
    assert resp.status_code == 502
    err = resp.json()["error"]
    assert err["code"] == "upstream_error" and err["details"] == {"status": 404}
    respx.get("https://example.com/500").mock(return_value=httpx.Response(503))
    assert (await fetch(client, "https://example.com/500")).json()["error"]["details"] == {
        "status": 503
    }
    respx.get("https://example.com/conn").mock(side_effect=httpx.ConnectError("refused"))
    resp = await fetch(client, "https://example.com/conn")
    assert resp.status_code == 502 and resp.json()["error"]["code"] == "upstream_error"
    respx.get("https://example.com/noloc").mock(return_value=httpx.Response(302))
    assert (await fetch(client, "https://example.com/noloc")).json()["error"][
        "code"
    ] == "upstream_error"


@respx.mock
async def test_timeout(client: Any) -> None:
    respx.get("https://example.com/slow").mock(side_effect=httpx.ReadTimeout("slow"))
    resp = await fetch(client, "https://example.com/slow")
    assert resp.status_code == 504 and resp.json()["error"]["code"] == "upstream_timeout"


async def test_total_timeout_enforced(new_client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    async def slow(host: str, port: int) -> list[str]:
        await asyncio.sleep(5)
        return ["93.184.216.34"]

    monkeypatch.setattr(ssrf, "resolve_host", slow)
    async with new_client(fetch_timeout_seconds=0.2) as c:
        resp = await fetch(c, "https://example.com/x")
        assert resp.status_code == 504 and resp.json()["error"]["code"] == "upstream_timeout"


@respx.mock
async def test_size_limit_content_length_and_streaming(new_client: Any) -> None:
    async with new_client(max_fetch_bytes=100) as c:
        respx.get("https://example.com/big").mock(
            return_value=httpx.Response(200, content=b"x" * 500, headers={"content-length": "500"})
        )
        resp = await fetch(c, "https://example.com/big")
        assert resp.status_code == 413 and resp.json()["error"]["code"] == "fetch_too_large"

        async def chunks() -> Any:
            for _ in range(10):
                yield b"y" * 50

        respx.get("https://example.com/stream").mock(
            return_value=httpx.Response(200, content=chunks())
        )
        resp = await fetch(c, "https://example.com/stream")
        assert resp.status_code == 413 and resp.json()["error"]["code"] == "fetch_too_large"
        respx.get("https://example.com/ok").mock(
            return_value=httpx.Response(200, content=b"[" + b"1," * 40 + b"1]")
        )
        assert (await fetch(c, "https://example.com/ok")).status_code == 200


async def test_validation_errors(client: Any) -> None:
    resp = await client.post("/api/fetch", json={})
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "validation_error"
    resp = await client.post(
        "/api/fetch", content=b"not json", headers={"content-type": "application/json"}
    )
    assert resp.status_code in (400, 422)
    assert "error" in resp.json()


async def test_works_without_cookies(client: Any) -> None:
    with respx.mock:
        respx.get("https://example.com/a").mock(return_value=httpx.Response(200, text="1"))
        assert not client.cookies
        assert (await fetch(client, "https://example.com/a")).status_code == 200
