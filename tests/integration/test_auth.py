from __future__ import annotations

import base64
import hashlib
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from authlib.jose import JsonWebKey, jwt
from sqlalchemy import select, text

from app.db.models import HistoryEntry, OAuthAccount, Session, Share, User
from app.domain.auth import providers as prov
from app.lib.security import token_hash
from tests.conftest import create_session, create_user, login

FRONTEND = "http://localhost:3000"
RSA = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "test-key"})
JWKS = {"keys": [RSA.as_dict(is_private=False)]}


@pytest.fixture(autouse=True)
def reset_jwks() -> None:
    prov.reset_jwks_cache()


def id_token(nonce: str | None, **overrides: Any) -> str:
    claims: dict[str, Any] = {
        "iss": "https://accounts.google.com",
        "aud": "google-id",
        "sub": "google-sub-1",
        "email": "alice@example.com",
        "email_verified": True,
        "name": "Alice",
        "picture": "https://img/alice.png",
        "nonce": nonce,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None or k == "nonce"}
    return jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, RSA).decode()


async def start(
    client: Any, provider: str, return_to: str | None = None
) -> tuple[dict[str, list[str]], Any]:
    url = f"/api/auth/{provider}/login" + (
        f"?return_to={return_to}" if return_to is not None else ""
    )
    resp = await client.get(url, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return parse_qs(urlsplit(resp.headers["location"]).query), resp


def mock_google(
    nonce: str | None, token: str | None = None, status: int = 200, **claims: Any
) -> respx.Route:
    respx.get("https://www.googleapis.com/oauth2/v3/certs").mock(
        return_value=httpx.Response(200, json=JWKS)
    )
    body = {
        "access_token": "at",
        "token_type": "Bearer",
        "id_token": token or id_token(nonce, **claims),
    }
    return respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            status, json=body if status == 200 else {"error": "invalid_grant"}
        )
    )


def mock_github(
    emails: list[dict[str, Any]] | None = None,
    user: dict[str, Any] | None = None,
    token_status: int = 200,
) -> None:
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(
            token_status,
            json={"access_token": "gho_x", "token_type": "bearer"}
            if token_status == 200
            else {"error": "bad_verification_code"},
        )
    )
    respx.get("https://api.github.com/user").mock(
        return_value=httpx.Response(
            200,
            json=user
            or {
                "id": 4242,
                "login": "octocat",
                "name": "The Octocat",
                "avatar_url": "https://img/octo.png",
            },
        )
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=httpx.Response(
            200,
            json=emails
            if emails is not None
            else [
                {"email": "secondary@example.com", "primary": False, "verified": True},
                {"email": "Octo@Example.com", "primary": True, "verified": True},
            ],
        )
    )


def location(resp: Any) -> str:
    return resp.headers["location"]


def cookie_headers(resp: Any) -> list[str]:
    return resp.headers.get_list("set-cookie")


# ------------------------------------------------------------------ providers / login redirect


async def test_providers_listing(client: Any, new_client: Any) -> None:
    assert (await client.get("/api/auth/providers")).json() == {"providers": ["google", "github"]}
    async with new_client(google_client_id="", github_client_secret="") as c:
        assert (await c.get("/api/auth/providers")).json() == {"providers": []}
        for provider in ("google", "github", "unknown"):
            resp = await c.get(f"/api/auth/{provider}/login", follow_redirects=False)
            assert resp.status_code == 404 and resp.json()["error"]["code"] == "provider_not_found"


async def test_google_login_redirect_parameters(client: Any) -> None:
    query, resp = await start(client, "google", "/history")
    url = urlsplit(location(resp))
    assert (
        f"{url.scheme}://{url.netloc}{url.path}" == "https://accounts.google.com/o/oauth2/v2/auth"
    )
    assert query["response_type"] == ["code"] and query["client_id"] == ["google-id"]
    assert query["scope"] == ["openid email profile"] and query["prompt"] == ["select_account"]
    assert query["code_challenge_method"] == ["S256"] and query["code_challenge"][0]
    assert query["redirect_uri"] == ["http://localhost:3000/api/auth/google/callback"]
    assert query["state"][0] and query["nonce"][0]
    cookie = next(c for c in cookie_headers(resp) if c.startswith("jv_oauth="))
    assert (
        "HttpOnly" in cookie
        and "Path=/api/auth" in cookie
        and "SameSite=lax" in cookie
        and "Max-Age=600" in cookie
    )
    assert "history" not in cookie  # sealed (encrypted), not readable
    assert resp.headers["cache-control"] == "no-store"


async def test_github_login_redirect_parameters(client: Any) -> None:
    query, resp = await start(client, "github")
    url = urlsplit(location(resp))
    assert url.netloc == "github.com" and url.path == "/login/oauth/authorize"
    assert query["scope"] == ["read:user user:email"] and query["code_challenge_method"] == ["S256"]
    assert "nonce" not in query and query["state"][0]


async def test_each_login_uses_fresh_state(client: Any) -> None:
    a, _ = await start(client, "github")
    b, _ = await start(client, "github")
    assert a["state"] != b["state"] and a["code_challenge"] != b["code_challenge"]


# ------------------------------------------------------------------ google flow


@respx.mock
async def test_google_full_login_flow(client: Any, db: Any) -> None:
    query, _ = await start(client, "google", "/history?tab=1")
    route = mock_google(query["nonce"][0])
    resp = await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert resp.status_code == 302 and location(resp) == f"{FRONTEND}/history?tab=1"

    sent = parse_qs(route.calls.last.request.content.decode())
    assert sent["code"] == ["abc"] and sent["grant_type"] == ["authorization_code"]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(sent["code_verifier"][0].encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert (
        challenge == query["code_challenge"][0]
    )  # PKCE verifier matches the challenge sent earlier

    cookies = cookie_headers(resp)
    session_cookie = next(c for c in cookies if c.startswith("jv_session="))
    assert (
        "HttpOnly" in session_cookie
        and "SameSite=lax" in session_cookie
        and "Path=/" in session_cookie
    )
    assert "Max-Age=2592000" in session_cookie and "Secure" not in session_cookie
    assert any(c.startswith("csrftoken=") for c in cookies)
    assert any(c.startswith("jv_oauth=") and ("Max-Age=0" in c or "1970" in c) for c in cookies)

    raw = client.cookies.get("jv_session")
    row = (await db.execute(select(Session))).scalar_one()
    assert (
        row.token_hash == token_hash(raw) and raw not in row.token_hash
    )  # only the hash is stored
    assert row.expires_at > datetime.now(UTC) + timedelta(days=29)

    me = (await client.get("/api/auth/me")).json()["user"]
    assert (
        me["email"] == "alice@example.com"
        and me["name"] == "Alice"
        and me["providers"] == ["google"]
    )
    assert me["avatar_url"] == "https://img/alice.png" and set(me) == {
        "id",
        "email",
        "name",
        "avatar_url",
        "providers",
        "created_at",
    }


@respx.mock
async def test_secure_cookie_flag_in_production_mode(make_app: Any) -> None:
    from litestar.testing import AsyncTestClient

    async with AsyncTestClient(
        app=make_app(cookie_secure=True), base_url="https://testserver"
    ) as c:
        query, _ = await start(c, "google")
        mock_google(query["nonce"][0])
        resp = await c.get(
            f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
        )
        assert "Secure" in next(x for x in cookie_headers(resp) if x.startswith("jv_session="))


@pytest.mark.parametrize("bad", ["//evil.com", "https://evil.com", "/\\evil.com", "evil.com"])
@respx.mock
async def test_open_redirect_blocked(client: Any, bad: str) -> None:
    query, _ = await start(client, "google", bad)
    mock_google(query["nonce"][0])
    resp = await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/"


@respx.mock
async def test_state_mismatch_and_missing_cookie(client: Any, new_client: Any, db: Any) -> None:
    query, _ = await start(client, "google")
    route = mock_google(query["nonce"][0])
    resp = await client.get(
        "/api/auth/google/callback?code=abc&state=forged", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=invalid_state"
    assert not route.called and (await db.execute(select(Session))).first() is None
    assert any(c.startswith("jv_oauth=") for c in cookie_headers(resp))  # cookie deleted
    async with new_client() as other:  # no jv_oauth cookie at all
        resp = await other.get(
            f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
        )
        assert location(resp) == f"{FRONTEND}/login?error=invalid_state"
        resp = await other.get("/api/auth/google/callback", follow_redirects=False)
        assert location(resp) == f"{FRONTEND}/login?error=invalid_state"


@respx.mock
async def test_state_cookie_is_bound_to_provider(client: Any) -> None:
    query, _ = await start(client, "google")
    mock_github()
    resp = await client.get(
        f"/api/auth/github/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=invalid_state"


@respx.mock
async def test_tampered_oauth_cookie(client: Any) -> None:
    query, _ = await start(client, "google")
    client.cookies.set("jv_oauth", "tampered", path="/api/auth")
    resp = await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=invalid_state"


async def test_cancelled_login(client: Any) -> None:
    query, _ = await start(client, "github")
    resp = await client.get(
        f"/api/auth/github/callback?error=access_denied&state={query['state'][0]}",
        follow_redirects=False,
    )
    assert location(resp) == f"{FRONTEND}/login?error=oauth_cancelled"
    resp = await client.get("/api/auth/github/callback", follow_redirects=False)
    assert location(resp).startswith(
        f"{FRONTEND}/login?error="
    )  # cookie was consumed -> invalid_state


@respx.mock
async def test_missing_code_and_disabled_provider(client: Any, new_client: Any) -> None:
    query, _ = await start(client, "github")
    resp = await client.get(
        f"/api/auth/github/callback?state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=oauth_failed"
    async with new_client(github_client_id="") as c:
        resp = await c.get("/api/auth/github/callback?code=x&state=y", follow_redirects=False)
        assert location(resp) == f"{FRONTEND}/login?error=provider_not_found"


@respx.mock
async def test_token_exchange_failure(client: Any, db: Any) -> None:
    query, _ = await start(client, "google")
    mock_google(query["nonce"][0], status=400)
    resp = await client.get(
        f"/api/auth/google/callback?code=bad&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=token_exchange_failed"
    assert (await db.execute(select(User))).first() is None and "jv_session" not in client.cookies


@pytest.mark.parametrize(
    "overrides",
    [
        {"nonce": "wrong-nonce"},
        {"aud": "someone-else"},
        {"iss": "https://evil.example"},
        {"exp": int(time.time()) - 100},
        {"sub": None},
    ],
)
@respx.mock
async def test_google_id_token_validation(client: Any, db: Any, overrides: dict[str, Any]) -> None:
    query, _ = await start(client, "google")
    nonce = query["nonce"][0]
    claims = dict(overrides)
    token_nonce = claims.pop("nonce", nonce)
    if "sub" in claims and claims["sub"] is None:
        token = jwt.encode(
            {"alg": "RS256", "kid": "test-key"},
            {
                "iss": "https://accounts.google.com",
                "aud": "google-id",
                "nonce": nonce,
                "exp": int(time.time()) + 100,
                "email": "a@b.c",
            },
            RSA,
        ).decode()
        mock_google(nonce, token=token)
    else:
        mock_google(nonce, token=id_token(token_nonce, **claims))
    resp = await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=invalid_identity"
    assert (await db.execute(select(User))).first() is None


@respx.mock
async def test_google_id_token_bad_signature_and_missing(client: Any, db: Any) -> None:
    query, _ = await start(client, "google")
    other = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "test-key"})
    forged = jwt.encode(
        {"alg": "RS256", "kid": "test-key"},
        {
            "iss": "https://accounts.google.com",
            "aud": "google-id",
            "sub": "x",
            "nonce": query["nonce"][0],
            "exp": int(time.time()) + 100,
        },
        other,
    ).decode()
    mock_google(query["nonce"][0], token=forged)
    resp = await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=invalid_identity"

    query, _ = await start(client, "google")
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "x"})
    )
    resp = await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=invalid_identity"


# ------------------------------------------------------------------ github flow


@respx.mock
async def test_github_flow_uses_primary_verified_email(client: Any, db: Any) -> None:
    query, _ = await start(client, "github", "/shares")
    mock_github()
    resp = await client.get(
        f"/api/auth/github/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/shares"
    me = (await client.get("/api/auth/me")).json()["user"]
    assert (
        me["email"] == "octo@example.com"
        and me["name"] == "The Octocat"
        and me["providers"] == ["github"]
    )
    account = (await db.execute(select(OAuthAccount))).scalar_one()
    assert account.provider_user_id == "4242" and account.provider_login == "octocat"
    api_calls = [c.request for c in respx.calls if c.request.url.host == "api.github.com"]
    assert (
        all(r.headers["authorization"] == "Bearer gho_x" for r in api_calls) and len(api_calls) == 2
    )
    token_req = parse_qs(
        next(c.request for c in respx.calls if c.request.url.host == "github.com").content.decode()
    )
    assert token_req["code_verifier"][0]


@pytest.mark.parametrize(
    "emails",
    [
        [],
        [{"email": "x@y.z", "primary": True, "verified": False}],
        [{"email": "x@y.z", "primary": False, "verified": True}],
    ],
)
@respx.mock
async def test_github_without_primary_verified_email(
    client: Any, db: Any, emails: list[dict[str, Any]]
) -> None:
    query, _ = await start(client, "github")
    mock_github(emails=emails)
    await client.get(
        f"/api/auth/github/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    user = (await db.execute(select(User))).scalar_one()
    assert user.email is None and user.email_verified is False


@respx.mock
async def test_github_failures(client: Any, db: Any) -> None:
    query, _ = await start(client, "github")
    mock_github(token_status=400)
    resp = await client.get(
        f"/api/auth/github/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=token_exchange_failed"
    query, _ = await start(client, "github")
    mock_github()
    respx.get("https://api.github.com/user").mock(return_value=httpx.Response(401, json={}))
    resp = await client.get(
        f"/api/auth/github/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/login?error=invalid_identity"
    assert (await db.execute(select(User))).first() is None


# ------------------------------------------------------------------ account linking


@respx.mock
async def test_links_by_verified_email(client: Any, db: Any) -> None:
    query, _ = await start(client, "github")
    mock_github(emails=[{"email": "shared@example.com", "primary": True, "verified": True}])
    await client.get(
        f"/api/auth/github/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    first = (await client.get("/api/auth/me")).json()["user"]
    client.cookies.clear()

    query, _ = await start(client, "google")
    mock_google(query["nonce"][0], email="Shared@Example.com", email_verified=True, sub="g-1")
    await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    second = (await client.get("/api/auth/me")).json()["user"]
    assert second["id"] == first["id"] and second["providers"] == ["github", "google"]
    assert len((await db.execute(select(User))).scalars().all()) == 1
    assert len((await db.execute(select(OAuthAccount))).scalars().all()) == 2


@respx.mock
async def test_no_linking_for_unverified_email(client: Any, db: Any) -> None:
    victim = await create_user(db, "victim@example.com", "Victim")
    query, _ = await start(client, "google")
    mock_google(query["nonce"][0], email="victim@example.com", email_verified=False, sub="attacker")
    resp = await client.get(
        f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
    )
    assert location(resp) == f"{FRONTEND}/"
    me = (await client.get("/api/auth/me")).json()["user"]
    assert me["id"] != str(victim.id) and me["email"] is None
    users = (await db.execute(select(User))).scalars().all()
    assert len(users) == 2
    accounts = (await db.execute(select(OAuthAccount))).scalars().all()
    assert len(accounts) == 1 and accounts[0].user_id != victim.id
    assert accounts[0].provider_email == "victim@example.com"


@respx.mock
async def test_returning_user_reuses_account_and_updates_profile(client: Any, db: Any) -> None:
    for name in ("Alice", "Alice Renamed"):
        client.cookies.clear()
        query, _ = await start(client, "google")
        mock_google(query["nonce"][0], name=name)
        await client.get(
            f"/api/auth/google/callback?code=abc&state={query['state'][0]}", follow_redirects=False
        )
    users = (await db.execute(select(User))).scalars().all()
    assert (
        len(users) == 1 and users[0].name == "Alice Renamed" and users[0].last_login_at is not None
    )
    assert len((await db.execute(select(Session))).scalars().all()) == 2


# ------------------------------------------------------------------ me / sessions / logout / delete


async def test_me_anonymous(client: Any) -> None:
    resp = await client.get("/api/auth/me")
    assert resp.status_code == 200 and resp.json() == {"user": None}


async def test_invalid_and_expired_session_cookies_are_anonymous(
    client: Any, db: Any, user: Any
) -> None:
    client.cookies.set("jv_session", "garbage")
    assert (await client.get("/api/auth/me")).json() == {"user": None}
    raw = await create_session(db, user, expires_in=timedelta(seconds=-5))
    client.cookies.set("jv_session", raw)
    assert (await client.get("/api/auth/me")).json() == {"user": None}
    assert (await client.get("/api/history")).status_code == 401


async def test_last_seen_updated_at_most_every_five_minutes(auth_client: Any, db: Any) -> None:
    row = (await db.execute(select(Session))).scalar_one()
    old = datetime.now(UTC) - timedelta(minutes=10)
    await db.execute(text("UPDATE sessions SET last_seen_at = :t"), {"t": old})
    await db.commit()
    await auth_client.get("/api/auth/me")
    await db.refresh(row)
    assert row.last_seen_at > datetime.now(UTC) - timedelta(minutes=1)
    stamp = row.last_seen_at
    await auth_client.get("/api/auth/me")
    await db.refresh(row)
    assert row.last_seen_at == stamp


async def test_logout(auth_client: Any, db: Any) -> None:
    resp = await auth_client.post("/api/auth/logout")
    assert resp.status_code == 204
    cleared = cookie_headers(resp)
    assert any(c.startswith("jv_session=") and ("Max-Age=0" in c or "1970" in c) for c in cleared)
    assert (await db.execute(select(Session))).first() is None
    assert (await auth_client.get("/api/auth/me")).json() == {"user": None}


async def test_logout_anonymous_is_idempotent(client: Any) -> None:
    assert (await client.post("/api/auth/logout")).status_code == 204


async def test_session_listing_and_revocation(
    auth_client: Any, db: Any, user: Any, new_client: Any
) -> None:
    other_raw = await create_session(db, user)
    other = await create_user(db, "someone@example.com")
    foreign_raw = await create_session(db, other)
    listing = (await auth_client.get("/api/auth/sessions")).json()
    assert len(listing) == 2 and sum(1 for s in listing if s["current"]) == 1
    assert {"id", "created_at", "last_seen_at", "expires_at", "user_agent", "ip", "current"} == set(
        listing[0]
    )
    foreign_id = str(
        (await db.execute(select(Session.id).where(Session.user_id == other.id))).scalar_one()
    )
    resp = await auth_client.delete(f"/api/auth/sessions/{foreign_id}")
    assert resp.status_code == 404  # cannot revoke someone else's session
    victim = next(s["id"] for s in listing if not s["current"])
    assert (await auth_client.delete(f"/api/auth/sessions/{victim}")).status_code == 204
    assert (await auth_client.delete(f"/api/auth/sessions/{victim}")).status_code == 404
    async with new_client() as c2:
        login(c2, other_raw)
        assert (await c2.get("/api/auth/me")).json() == {"user": None}  # revoked session is dead
    assert foreign_raw


async def test_revoke_all_other_sessions(auth_client: Any, db: Any, user: Any) -> None:
    for _ in range(3):
        await create_session(db, user)
    assert (await auth_client.delete("/api/auth/sessions")).status_code == 204
    listing = (await auth_client.get("/api/auth/sessions")).json()
    assert len(listing) == 1 and listing[0]["current"] is True


async def test_account_deletion_cascades(auth_client: Any, db: Any, user: Any) -> None:
    db.add(OAuthAccount(user_id=user.id, provider="github", provider_user_id="1"))  # type: ignore[arg-type]
    await db.commit()
    share = (
        await auth_client.post("/api/shares", json={"content": "[1]", "save_to_history": True})
    ).json()
    assert (
        await auth_client.post("/api/history", json={"content": "[2]", "source": "manual"})
    ).status_code == 201
    resp = await auth_client.delete("/api/auth/account")
    assert resp.status_code == 204
    assert any(c.startswith("jv_session=") for c in cookie_headers(resp))
    db.expire_all()
    assert (await db.execute(select(User))).first() is None
    assert (await db.execute(select(OAuthAccount))).first() is None
    assert (await db.execute(select(Session))).first() is None
    assert (await db.execute(select(HistoryEntry))).first() is None
    kept = (await db.execute(select(Share))).scalar_one()  # shares survive with owner_id = NULL
    assert kept.slug == share["slug"] and kept.owner_id is None
    assert (await auth_client.get("/api/auth/me")).json() == {"user": None}


async def test_auth_required_endpoints(client: Any) -> None:
    for method, url in [
        ("GET", "/api/auth/sessions"),
        ("DELETE", "/api/auth/sessions"),
        ("DELETE", "/api/auth/account"),
        ("GET", "/api/shares"),
    ]:
        resp = await client.request(method, url)
        assert resp.status_code == 401 and resp.json()["error"]["code"] == "auth_required", url
