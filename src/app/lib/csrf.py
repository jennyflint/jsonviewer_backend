from __future__ import annotations

import re
from urllib.parse import urlsplit

from litestar.config.csrf import CSRFConfig
from litestar.enums import ScopeType
from litestar.middleware.csrf import CSRFMiddleware
from litestar.types import ASGIApp, Receive, Scope, Send

from app.config import Settings
from app.lib.errors import PermissionDenied
from app.lib.security import CSRF_COOKIE

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope["headers"]:
        if key == name:
            return value.decode("latin-1")
    return None


def _cookie(scope: Scope, name: str) -> str | None:
    raw = _header(scope, b"cookie")
    if not raw:
        return None
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return None


def make_csrf_config(settings: Settings) -> CSRFConfig:
    return CSRFConfig(
        secret=settings.secret_key,
        cookie_name=CSRF_COOKIE,
        header_name="X-CSRF-Token",
        cookie_secure=settings.cookie_secure,
        cookie_samesite="lax",
        cookie_httponly=False,
        exclude=[rf"^{re.escape(settings.api_prefix.rstrip('/'))}/auth/[^/]+/callback$"],
    )


class ConditionalCSRFMiddleware:
    """Litestar's double-submit CSRF protection, applied only to cookie-authenticated requests.

    Anonymous requests carry no ambient credentials, so they pass untouched. In addition, any
    unsafe request whose Origin header is present must come from an allowed origin.
    """

    def __init__(self, app: ASGIApp, settings: Settings, config: CSRFConfig) -> None:
        self.app = app
        self.settings = settings
        self.inner = CSRFMiddleware(app, config)
        self.exclude = config.exclude

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != ScopeType.HTTP:
            await self.app(scope, receive, send)
            return
        unsafe = scope["method"] not in SAFE_METHODS
        if unsafe:
            self._check_origin(scope)
        if _cookie(scope, self.settings.session_cookie_name) is None or self._excluded(
            scope["path"]
        ):
            await self.app(scope, receive, send)
            return
        if unsafe:
            header = _header(scope, b"x-csrf-token")
            cookie = _cookie(scope, CSRF_COOKIE)
            if not header or not cookie or not self.inner._csrf_tokens_match(header, cookie):
                raise PermissionDenied("CSRF token missing or invalid.", code="csrf_failed")
        await self.inner(scope, receive, send)

    def _excluded(self, path: str) -> bool:
        return any(re.match(p, path) for p in self.exclude or [])

    def _check_origin(self, scope: Scope) -> None:
        origin = _header(scope, b"origin")
        if origin is None:
            return
        if origin in self.settings.allowed_origins:
            return
        host = _header(scope, b"host")
        if host and urlsplit(origin).netloc == host:
            return
        raise PermissionDenied("Origin not allowed.", code="origin_not_allowed")
