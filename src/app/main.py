from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from typing import Any

import click
from advanced_alchemy.extensions.litestar import (
    EngineConfig,
    SQLAlchemyAsyncConfig,
    SQLAlchemyPlugin,
)
from litestar import Litestar, Request, Router, get, route
from litestar.config.cors import CORSConfig
from litestar.di import Provide
from litestar.middleware import DefineMiddleware
from litestar.openapi import OpenAPIConfig
from litestar.openapi.controller import OpenAPIController
from litestar.openapi.plugins import ScalarRenderPlugin, SwaggerRenderPlugin
from litestar.plugins import CLIPluginProtocol
from litestar.stores.redis import RedisStore

from app.config import VERSION, Settings, get_settings
from app.db.base import Base
from app.domain.analysis.controller import AnalysisController
from app.domain.auth.controller import AuthController
from app.domain.auth.guards import AuthMiddleware, provide_auth_context, provide_current_user
from app.domain.fetch.controller import FetchController
from app.domain.history.controller import HistoryController
from app.domain.shares.controller import ShareController
from app.domain.system.controller import SystemController
from app.lib.csrf import ConditionalCSRFMiddleware, make_csrf_config
from app.lib.errors import EXCEPTION_HANDLERS, NotFound
from app.lib.logging import RequestContextMiddleware, add_security_headers, setup_logging
from app.lib.rate_limit import RateLimits
from app.tasks.cleanup import cleanup_loop, run_cleanup, stop_task


class CleanupCLIPlugin(CLIPluginProtocol):
    """Adds ``litestar --app app.main:app cleanup`` for manual or cron runs."""

    def on_cli_init(self, cli: click.Group) -> None:
        @cli.command(name="cleanup", help="Delete expired shares and sessions.")
        def cleanup(app: Litestar) -> None:
            async def _run() -> None:
                configs = app.plugins.get(SQLAlchemyPlugin).config
                config = configs[0] if isinstance(configs, Sequence) else configs
                assert isinstance(config, SQLAlchemyAsyncConfig)
                engine = config.get_engine()
                result = await run_cleanup(engine)
                click.echo(
                    "skipped (another instance holds the lock)" if result is None else str(result)
                )
                await engine.dispose()

            asyncio.run(_run())


def create_app(settings: Settings | None = None) -> Litestar:
    settings = settings or get_settings()
    setup_logging(settings.log_level)
    prefix = settings.api_prefix.rstrip("/")
    limits = RateLimits(settings)

    db_config = SQLAlchemyAsyncConfig(
        connection_string=settings.database_url,
        metadata=Base.metadata,
        before_send_handler="autocommit_include_redirects",
        engine_config=EngineConfig(pool_size=settings.db_pool_size, pool_pre_ping=True),
        set_default_exception_handler=False,
    )

    @asynccontextmanager
    async def lifespan(app: Litestar) -> AsyncGenerator[None, None]:
        task: asyncio.Task[None] | None = None
        if settings.cleanup_interval_seconds > 0:
            task = asyncio.create_task(
                cleanup_loop(db_config.get_engine(), settings.cleanup_interval_seconds)
            )
        try:
            yield
        finally:
            if task is not None:
                await stop_task(task)

    shares_limit = limits.shares
    shares_limit.check_throttle_handler = _only_post

    api = Router(
        path=prefix,
        route_handlers=[
            SystemController,
            Router(path="", middleware=[limits.fetch.middleware], route_handlers=[FetchController]),
            Router(path="", middleware=[shares_limit.middleware], route_handlers=[ShareController]),
            Router(
                path="",
                middleware=[limits.analysis.middleware],
                route_handlers=[AnalysisController],
            ),
            Router(path="", middleware=[limits.auth.middleware], route_handlers=[AuthController]),
            HistoryController,
        ],
    )

    @route(
        f"{prefix}/{{path:path}}",
        http_method=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
        sync_to_thread=False,
    )
    def not_found_fallback(path: str) -> None:
        # Unmatched URLs go through the middleware stack too (request id, headers, logging).
        raise NotFound()

    @get(f"{prefix}/openapi.json", include_in_schema=False, sync_to_thread=False)
    def openapi_json(request: Request[Any, Any, Any]) -> dict[str, Any]:
        return request.app.openapi_schema.to_schema()

    class Docs(OpenAPIController):
        path = f"{prefix}/docs"

    openapi_config = (
        OpenAPIConfig(
            title="JSON Viewer API",
            version=VERSION,
            description="REST API: shares, remote fetch, duplicate analysis, history.",
            path=f"{prefix}/docs",
            openapi_controller=Docs,
            render_plugins=[ScalarRenderPlugin(), SwaggerRenderPlugin(path="/swagger")],
        )
        if settings.openapi_enabled
        else None
    )

    stores: dict[str, Any] = {}
    if settings.rate_limit_store == "redis":
        stores["rate_limit"] = RedisStore.with_client(url=settings.redis_url)

    handlers: list[Any] = [api, not_found_fallback]
    if settings.openapi_enabled:
        handlers.append(openapi_json)

    return Litestar(
        route_handlers=handlers,
        plugins=[SQLAlchemyPlugin(config=db_config), CleanupCLIPlugin()],
        dependencies={
            "settings": Provide(lambda: settings, sync_to_thread=False),
            "current_user": Provide(provide_current_user, sync_to_thread=False),
            "auth_ctx": Provide(provide_auth_context, sync_to_thread=False),
        },
        middleware=[
            DefineMiddleware(RequestContextMiddleware, api_prefix=prefix),
            DefineMiddleware(
                ConditionalCSRFMiddleware, settings=settings, config=make_csrf_config(settings)
            ),
            DefineMiddleware(AuthMiddleware, settings=settings, get_engine=db_config.get_engine),
            limits.default.middleware,
        ],
        cors_config=CORSConfig(
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Content-Type",
                "X-CSRF-Token",
                "X-Delete-Token",
                "X-Request-ID",
                "X-Share-Password",
            ],
        ),
        exception_handlers=EXCEPTION_HANDLERS,
        openapi_config=openapi_config,
        # JSON-escaped documents can be up to ~2x their size; a comparison carries two of them
        request_max_body_size=max(settings.max_fetch_bytes, settings.max_document_bytes * 2)
        + 1024 * 1024,
        stores=stores or None,
        before_send=[add_security_headers],
        lifespan=[lifespan],
        logging_config=None,
        debug=False,
    )


async def _only_post(request: Request[Any, Any, Any]) -> bool:
    return request.method == "POST"


_app: Litestar | None = None


def __getattr__(name: str) -> Any:
    """Lazily build ``app`` so importing this module needs no environment (uvicorn app.main:app)."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
