from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from litestar import Request
from litestar.connection import ASGIConnection
from litestar.enums import ScopeType
from litestar.handlers.base import BaseRouteHandler
from litestar.types import ASGIApp, Receive, Scope, Send
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.config import Settings
from app.db.models import Session, User
from app.lib.errors import NotAuthorized
from app.lib.security import token_hash

AUTH_SCOPE_KEY = "jv_auth"
LAST_SEEN_INTERVAL = timedelta(minutes=5)


@dataclass(slots=True)
class AuthContext:
    user: User
    session_id: Any
    token_hash: str


class AuthMiddleware:
    """Resolves the session cookie into an AuthContext (or None for anonymous requests)."""

    def __init__(
        self, app: ASGIApp, settings: Settings, get_engine: Callable[[], AsyncEngine]
    ) -> None:
        self.app = app
        self.settings = settings
        self.get_engine = get_engine

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == ScopeType.HTTP:
            scope[AUTH_SCOPE_KEY] = None  # type: ignore[literal-required]
            raw = _cookie(scope, self.settings.session_cookie_name)
            if raw:
                scope[AUTH_SCOPE_KEY] = await self._resolve(self.get_engine(), raw)  # type: ignore[literal-required]
        await self.app(scope, receive, send)

    async def _resolve(self, engine: AsyncEngine, raw: str) -> AuthContext | None:
        hashed = token_hash(raw)
        now = datetime.now(UTC)
        async with AsyncSession(engine, expire_on_commit=False) as db:
            sess = (
                await db.execute(
                    select(Session).where(Session.token_hash == hashed, Session.expires_at > now)
                )
            ).scalar_one_or_none()
            if sess is None:
                return None
            if now - sess.last_seen_at > LAST_SEEN_INTERVAL:
                await db.execute(
                    update(Session).where(Session.id == sess.id).values(last_seen_at=now)
                )
                await db.commit()
            return AuthContext(user=sess.user, session_id=sess.id, token_hash=hashed)


def _cookie(scope: Scope, name: str) -> str | None:
    for key, value in scope["headers"]:
        if key == b"cookie":
            for part in value.decode("latin-1").split(";"):
                k, _, v = part.strip().partition("=")
                if k == name:
                    return v
    return None


def get_auth(connection: ASGIConnection[Any, Any, Any, Any]) -> AuthContext | None:
    ctx: AuthContext | None = connection.scope.get(AUTH_SCOPE_KEY)  # type: ignore[assignment]
    return ctx


def requires_auth(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    if get_auth(connection) is None:
        raise NotAuthorized()


def provide_current_user(request: Request[Any, Any, Any]) -> User | None:
    ctx = get_auth(request)
    return ctx.user if ctx else None


def provide_auth_context(request: Request[Any, Any, Any]) -> AuthContext | None:
    return get_auth(request)


def provide_required_user(request: Request[Any, Any, Any]) -> User:
    ctx = get_auth(request)
    if ctx is None:
        raise NotAuthorized()
    return ctx.user
