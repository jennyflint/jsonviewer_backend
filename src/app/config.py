from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VERSION = "1.0.0"


class Settings(BaseSettings):
    """Application settings, read from environment variables. Required values fail fast."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # App
    app_env: Literal["development", "production", "test"] = "development"
    secret_key: str = Field(min_length=16)
    api_prefix: str = "/api"
    frontend_url: str = "http://localhost:3000"
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    log_level: str = "INFO"
    uvicorn_workers: int = 2
    openapi_enabled: bool = True

    # Database
    database_url: str
    db_pool_size: int = 10

    # OAuth
    oauth_redirect_base_url: str = "http://localhost:3000/api/auth"
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""

    # Sessions
    session_cookie_name: str = "jv_session"
    session_ttl_days: int = 30
    cookie_secure: bool = False

    # Limits
    max_document_bytes: int = 15_728_640
    max_fetch_bytes: int = 15_728_640
    fetch_timeout_seconds: float = 10
    fetch_max_redirects: int = 3
    history_max_entries_per_user: int = 500
    rate_limit_store: Literal["memory", "redis"] = "memory"
    redis_url: str = ""
    # Multiplies every rate limit (tests use a large value to avoid interference).
    rate_limit_multiplier: int = 1
    cleanup_interval_seconds: int = 900

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if self.rate_limit_store == "redis" and not self.redis_url:
            raise ValueError("REDIS_URL is required when RATE_LIMIT_STORE=redis")
        if self.app_env == "production" and self.secret_key.startswith("change-me"):
            raise ValueError("SECRET_KEY must be changed in production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_origins(self) -> set[str]:
        origins = set(self.cors_origin_list)
        origins.add(self.frontend_url.rstrip("/"))
        return origins

    def provider_enabled(self, provider: str) -> bool:
        if provider == "google":
            return bool(self.google_client_id and self.google_client_secret)
        if provider == "github":
            return bool(self.github_client_id and self.github_client_secret)
        return False

    @property
    def enabled_providers(self) -> list[str]:
        return [p for p in ("google", "github") if self.provider_enabled(p)]


@lru_cache
def get_settings() -> Settings:
    return Settings()
