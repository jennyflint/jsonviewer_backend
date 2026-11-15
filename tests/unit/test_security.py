from __future__ import annotations

import pytest

from app.config import Settings
from app.lib.security import (
    SLUG_ALPHABET,
    generate_slug,
    pkce_challenge,
    random_token,
    seal,
    token_hash,
    tokens_equal,
    unseal,
    validate_return_to,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/history", "/history"),
        ("/a/b?x=1&y=2", "/a/b?x=1&y=2"),
        ("/", "/"),
        (None, "/"),
        ("", "/"),
        ("//evil.com", "/"),
        ("//evil.com/path", "/"),
        ("https://evil.com", "/"),
        ("http://evil.com/x", "/"),
        ("evil.com", "/"),
        ("history", "/"),
        ("/\\evil.com", "/"),
        ("\\\\evil.com", "/"),
        ("/path\\..\\x", "/"),
        ("javascript:alert(1)", "/"),
        ("/a\nb", "/"),
        ("/a\r\nSet-Cookie: x=1", "/"),
        ("/redirect://x", "/"),
    ],
)
def test_return_to_validation(value: str | None, expected: str) -> None:
    assert validate_return_to(value) == expected


def test_slug_and_tokens() -> None:
    slug = generate_slug()
    assert len(slug) == 12 and set(slug) <= set(SLUG_ALPHABET)
    assert generate_slug() != generate_slug()
    assert len(random_token(32)) >= 43
    assert len(token_hash("x")) == 64 and token_hash("x") == token_hash("x")
    assert tokens_equal("a", "a") and not tokens_equal("a", "b")


def test_pkce_rfc7636_vector() -> None:
    assert (
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_sealed_cookie_roundtrip_and_tamper() -> None:
    settings = Settings(secret_key="s" * 32, database_url="postgresql+asyncpg://x")  # type: ignore[call-arg]
    token = seal(settings, {"state": "abc"})
    assert unseal(settings, token) == {"state": "abc"}
    assert unseal(settings, token[:-3] + "AAA") is None
    assert unseal(settings, "garbage") is None
    other = Settings(secret_key="t" * 32, database_url="postgresql+asyncpg://x")  # type: ignore[call-arg]
    assert unseal(other, token) is None
    assert unseal(settings, token, ttl=-1) is None


def test_settings_validation() -> None:
    with pytest.raises(ValueError):
        Settings(secret_key="short", database_url="x")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(secret_key="s" * 32, database_url="x", rate_limit_store="redis")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(secret_key="change-me-" + "x" * 20, database_url="x", app_env="production")  # type: ignore[call-arg]
    s = Settings(
        secret_key="s" * 32, database_url="x", google_client_id="a", google_client_secret="b"
    )  # type: ignore[call-arg]
    assert s.enabled_providers == ["google"] and s.provider_enabled("github") is False
    assert "http://localhost:3000" in s.allowed_origins
