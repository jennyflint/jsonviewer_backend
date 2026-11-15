from __future__ import annotations

from typing import Any

from litestar import Request
from litestar.middleware.rate_limit import DurationUnit, RateLimitConfig

from app.config import Settings


def _identifier(group: str) -> Any:
    def identifier(request: Request[Any, Any, Any]) -> str:
        host = request.client.host if request.client else "unknown"
        return f"{group}:{host}"

    return identifier


def make_config(
    group: str, unit: DurationUnit, count: int, settings: Settings, **kw: Any
) -> RateLimitConfig:
    return RateLimitConfig(
        rate_limit=(unit, count * settings.rate_limit_multiplier),
        identifier_for_request=_identifier(group),
        **kw,
    )


class RateLimits:
    """Separate rate-limit configs per route group."""

    def __init__(self, settings: Settings) -> None:
        self.fetch = make_config("fetch", "minute", 20, settings)
        self.shares = make_config("shares", "hour", 30, settings)
        self.analysis = make_config("analysis", "minute", 60, settings)
        self.auth = make_config("auth", "minute", 30, settings)
        self.default = make_config(
            "default",
            "minute",
            300,
            settings,
            exclude=[
                f"^{p}/{g}"
                for p in [settings.api_prefix.rstrip("/")]
                for g in ("fetch", "auth", "analysis", "health")
            ],
        )
