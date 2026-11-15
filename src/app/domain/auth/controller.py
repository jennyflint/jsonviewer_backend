from __future__ import annotations

import hmac
import uuid
from typing import Annotated, Any
from urllib.parse import quote

import structlog
from litestar import Controller, Request, Response, delete, get, post
from litestar.di import Provide
from litestar.params import Parameter
from litestar.response import Redirect
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.db.models import User
from app.domain.auth.guards import AuthContext, requires_auth
from app.domain.auth.providers import OAuthError, get_provider
from app.domain.auth.schemas import MeResponse, ProvidersResponse, SessionOut, UserOut
from app.domain.auth.service import AuthService
from app.lib.errors import NotAuthorized, NotFound
from app.lib.security import (
    CSRF_COOKIE,
    OAUTH_COOKIE,
    csrf_cookie,
    oauth_cookie,
    oauth_cookie_path,
    random_token,
    session_cookie,
    tokens_equal,
    unseal,
    validate_return_to,
)

logger = structlog.get_logger()


async def provide_auth_service(db_session: AsyncSession, settings: Settings) -> AuthService:
    return AuthService(db_session, settings)


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=str(user.id),
        email=user.email,
        name=user.name,
        avatar_url=user.avatar_url,
        providers=sorted({a.provider.value for a in user.oauth_accounts}),
        created_at=user.created_at,
    )


def _login_error(settings: Settings, code: str) -> Redirect:
    redirect = Redirect(
        path=f"{settings.frontend_url.rstrip('/')}/login?error={quote(code)}", status_code=302
    )
    redirect.delete_cookie(OAUTH_COOKIE, path=oauth_cookie_path(settings))
    return redirect


def _clear_auth_cookies(response: Response[Any], settings: Settings) -> None:
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


class AuthController(Controller):
    path = "/auth"
    tags = ["Auth"]
    dependencies = {"service": Provide(provide_auth_service)}

    @get("/providers", summary="List enabled OAuth providers")
    async def providers(self, settings: Settings) -> ProvidersResponse:
        return ProvidersResponse(providers=settings.enabled_providers)

    @get("/me", summary="Current user (null when anonymous)")
    async def me(self, current_user: User | None) -> MeResponse:
        return MeResponse(user=_user_out(current_user) if current_user else None)

    @get("/{provider:str}/login", summary="Start OAuth login", status_code=302)
    async def login(
        self, provider: str, settings: Settings, return_to: str | None = None
    ) -> Redirect:
        impl = get_provider(provider, settings)
        if impl is None:
            raise NotFound("OAuth provider not found or disabled.", code="provider_not_found")
        state = random_token(32)
        verifier = random_token(64)
        nonce = random_token(16) if provider == "google" else None
        target = impl.authorization_url(state, verifier, nonce)
        redirect = Redirect(path=target, status_code=302, cookies=[])
        redirect.cookies.append(
            oauth_cookie(
                settings,
                {
                    "state": state,
                    "verifier": verifier,
                    "nonce": nonce,
                    "return_to": validate_return_to(return_to),
                    "provider": provider,
                },
            )
        )
        return redirect

    @get("/{provider:str}/callback", summary="OAuth callback", status_code=302)
    async def callback(
        self,
        provider: str,
        request: Request[Any, Any, Any],
        settings: Settings,
        service: AuthService,
        db_session: AsyncSession,
        code: str | None = None,
        oauth_state: Annotated[str | None, Parameter(query="state")] = None,
        error: str | None = None,
    ) -> Redirect:
        impl = get_provider(provider, settings)
        if impl is None:
            return _login_error(settings, "provider_not_found")
        sealed = request.cookies.get(OAUTH_COOKIE)
        data = unseal(settings, sealed) if sealed else None
        if (
            data is None
            or oauth_state is None
            or not tokens_equal(str(data.get("state", "")), oauth_state)
            or not hmac.compare_digest(str(data.get("provider", "")), provider)
        ):
            logger.warning("oauth_invalid_state", provider=provider)
            return _login_error(settings, "invalid_state")
        if error:
            logger.info("oauth_provider_error", provider=provider, error=error[:50])
            return _login_error(settings, "oauth_cancelled")
        if not code:
            return _login_error(settings, "oauth_failed")
        try:
            identity = await impl.identify(code, str(data["verifier"]), data.get("nonce"))
            user = await service.resolve_user(identity)
            ip = request.client.host if request.client else None
            raw = await service.create_session(user, request.headers.get("user-agent"), ip)
        except OAuthError as exc:
            logger.warning("oauth_failed", provider=provider, code=exc.code)
            await db_session.rollback()
            return _login_error(settings, exc.code)
        except Exception:
            logger.exception("oauth_unexpected_error", provider=provider)
            await db_session.rollback()
            return _login_error(settings, "oauth_failed")

        return_to = validate_return_to(data.get("return_to"))
        redirect = Redirect(
            path=f"{settings.frontend_url.rstrip('/')}{return_to}",
            status_code=302,
            cookies=[session_cookie(settings, raw), csrf_cookie(settings)],
        )
        redirect.delete_cookie(OAUTH_COOKIE, path=oauth_cookie_path(settings))
        return redirect

    @post("/logout", summary="Log out", status_code=204)
    async def logout(
        self, request: Request[Any, Any, Any], settings: Settings, service: AuthService
    ) -> Response[None]:
        raw = request.cookies.get(settings.session_cookie_name)
        if raw:
            await service.delete_by_token(raw)
        response: Response[None] = Response(None, status_code=204)
        _clear_auth_cookies(response, settings)
        return response

    @get("/sessions", summary="List active sessions", guards=[requires_auth])
    async def list_sessions(
        self, service: AuthService, auth_ctx: AuthContext | None
    ) -> list[SessionOut]:
        assert auth_ctx is not None
        sessions = await service.list_sessions(auth_ctx.user.id)
        return [
            SessionOut(
                id=str(s.id),
                created_at=s.created_at,
                last_seen_at=s.last_seen_at,
                expires_at=s.expires_at,
                user_agent=s.user_agent,
                ip=str(s.ip) if s.ip else None,
                current=s.id == auth_ctx.session_id,
            )
            for s in sessions
        ]

    @delete(
        "/sessions/{session_id:uuid}",
        summary="Revoke a session",
        status_code=204,
        guards=[requires_auth],
    )
    async def revoke_session(
        self, session_id: uuid.UUID, service: AuthService, auth_ctx: AuthContext | None
    ) -> None:
        assert auth_ctx is not None
        if not await service.revoke_session(auth_ctx.user.id, session_id):
            raise NotFound("Session not found.", code="session_not_found")

    @delete(
        "/sessions", summary="Revoke all other sessions", status_code=204, guards=[requires_auth]
    )
    async def revoke_other_sessions(
        self, service: AuthService, auth_ctx: AuthContext | None
    ) -> None:
        assert auth_ctx is not None
        await service.revoke_others(auth_ctx.user.id, auth_ctx.session_id)

    @delete("/account", summary="Delete my account", status_code=204, guards=[requires_auth])
    async def delete_account(
        self, service: AuthService, auth_ctx: AuthContext | None, settings: Settings
    ) -> Response[None]:
        if auth_ctx is None:
            raise NotAuthorized()
        await service.delete_account(auth_ctx.user.id)
        response: Response[None] = Response(None, status_code=204)
        _clear_auth_cookies(response, settings)
        return response
