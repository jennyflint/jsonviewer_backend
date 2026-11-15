from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import timedelta
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from litestar import Response
from litestar.datastructures import Cookie
from litestar.middleware.csrf import generate_csrf_token

from app.config import Settings

SLUG_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
CSRF_COOKIE = "csrftoken"
OAUTH_COOKIE = "jv_oauth"
OAUTH_COOKIE_TTL = 600


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def generate_slug(length: int = 12) -> str:
    return "".join(secrets.choice(SLUG_ALPHABET) for _ in range(length))


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _fernet(settings: Settings) -> Fernet:
    key = hashlib.sha256(b"jv-oauth-cookie:" + settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def seal(settings: Settings, data: dict[str, Any]) -> str:
    return _fernet(settings).encrypt(json.dumps(data).encode()).decode()


def unseal(settings: Settings, token: str, ttl: int = OAUTH_COOKIE_TTL) -> dict[str, Any] | None:
    try:
        raw = _fernet(settings).decrypt(token.encode(), ttl=ttl)
        data = json.loads(raw)
    except (InvalidToken, ValueError):
        return None
    return data if isinstance(data, dict) else None


def validate_return_to(value: str | None) -> str:
    """Only relative paths starting with a single '/' are allowed (prevents open redirects)."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if any(ord(c) < 32 for c in value) or "://" in value.split("?", 1)[0]:
        return "/"
    return value


def session_cookie(settings: Settings, token: str) -> Cookie:
    return Cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=int(timedelta(days=settings.session_ttl_days).total_seconds()),
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )


def csrf_cookie(settings: Settings) -> Cookie:
    return Cookie(
        key=CSRF_COOKIE,
        value=generate_csrf_token(secret=settings.secret_key),
        max_age=int(timedelta(days=settings.session_ttl_days).total_seconds()),
        path="/",
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
    )


def oauth_cookie_path(settings: Settings) -> str:
    return f"{settings.api_prefix.rstrip('/')}/auth"


def oauth_cookie(settings: Settings, payload: dict[str, Any]) -> Cookie:
    return Cookie(
        key=OAUTH_COOKIE,
        value=seal(settings, payload),
        max_age=OAUTH_COOKIE_TTL,
        path=oauth_cookie_path(settings),
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )


def clear_cookie(response: Response[Any], key: str, path: str = "/") -> None:
    response.delete_cookie(key, path=path)
