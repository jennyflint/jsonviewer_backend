from __future__ import annotations

import logging
import sys
import time
import uuid
from typing import Any

import structlog
from litestar.enums import ScopeType
from litestar.types import ASGIApp, Message, Receive, Scope, Send


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )


class RequestContextMiddleware:
    """Generates/propagates X-Request-ID, logs each request once, adds security headers."""

    def __init__(self, app: ASGIApp, api_prefix: str = "/api") -> None:
        self.app = app
        self.api_prefix = api_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != ScopeType.HTTP:
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        raw = headers.get("x-request-id", "")
        request_id = raw if raw and len(raw) <= 100 and raw.isprintable() else uuid.uuid4().hex
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        start = time.perf_counter()
        status = 500
        path: str = scope["path"]
        no_store = path.startswith(f"{self.api_prefix}/auth") or path.startswith(
            f"{self.api_prefix}/history"
        )

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                hdrs = list(message.get("headers", []))
                existing = {h[0].lower() for h in hdrs}
                extra: list[tuple[bytes, bytes]] = [
                    (b"x-request-id", request_id.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                ]
                if no_store:
                    extra.append((b"cache-control", b"no-store"))
                for k, v in extra:
                    if k not in existing or k == b"cache-control":
                        hdrs = [h for h in hdrs if h[0].lower() != k]
                        hdrs.append((k, v))
                message["headers"] = hdrs
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            auth: Any = scope.get("jv_auth")
            structlog.get_logger("access").info(
                "request",
                method=scope["method"],
                path=path,
                status=status,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
                user_id=str(auth.user.id) if auth else None,
            )
            structlog.contextvars.clear_contextvars()


def add_security_headers(message: Message, scope: Scope) -> None:
    """``before_send`` hook: security headers even on router-level errors (405, ...)."""
    if message["type"] != "http.response.start":
        return
    headers = list(message.get("headers", []))
    present = {h[0].lower() for h in headers}
    if b"x-content-type-options" not in present:
        headers.append((b"x-content-type-options", b"nosniff"))
    if b"referrer-policy" not in present:
        headers.append((b"referrer-policy", b"strict-origin-when-cross-origin"))
    message["headers"] = headers
