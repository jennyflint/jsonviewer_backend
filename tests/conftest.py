from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import asyncpg
import pytest
import pytest_asyncio
from litestar.middleware.csrf import generate_csrf_token
from litestar.testing import AsyncTestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

ROOT = Path(__file__).resolve().parents[1]
SECRET = "test-secret-key-0123456789abcdef"
TEST_DB_NAME = "jsonviewer_test"

os.environ.setdefault("SECRET_KEY", SECRET)


def _admin_and_test_urls() -> tuple[str, str, Any]:
    """Return (asyncpg dsn for admin db, sqlalchemy url for test db, container or None)."""
    base = os.environ.get("TEST_DATABASE_URL")
    container = None
    if not base:
        from testcontainers.postgres import PostgresContainer

        container = PostgresContainer("postgres:16-alpine", driver=None)
        container.start()
        base = (
            f"postgresql+asyncpg://{container.username}:{container.password}"
            f"@{container.get_container_host_ip()}:{container.get_exposed_port(5432)}/{container.dbname}"
        )
    head, _, _ = base.rpartition("/")
    admin_dsn = head.replace("postgresql+asyncpg://", "postgresql://") + "/postgres"
    return admin_dsn, f"{head}/{TEST_DB_NAME}", container


@pytest.fixture(scope="session")
def database_url() -> Any:
    import asyncio

    admin_dsn, url, container = _admin_and_test_urls()

    async def _recreate() -> None:
        conn = await asyncpg.connect(admin_dsn)
        try:
            await conn.execute(f"DROP DATABASE IF EXISTS {TEST_DB_NAME} WITH (FORCE)")
            await conn.execute(f"CREATE DATABASE {TEST_DB_NAME}")
        finally:
            await conn.close()

    asyncio.run(_recreate())
    env = {**os.environ, "DATABASE_URL": url}
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
    )
    yield url
    if container is not None:
        container.stop()


@pytest.fixture(scope="session")
def settings_factory(database_url: str) -> Callable[..., Any]:
    from app.config import Settings

    def make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "app_env": "test",
            "secret_key": SECRET,
            "database_url": database_url,
            "frontend_url": "http://localhost:3000",
            "oauth_redirect_base_url": "http://localhost:3000/api/auth",
            "google_client_id": "google-id",
            "google_client_secret": "google-secret",
            "github_client_id": "github-id",
            "github_client_secret": "github-secret",
            "rate_limit_multiplier": 1000,
            "cleanup_interval_seconds": 0,
            "history_max_entries_per_user": 500,
            "db_pool_size": 5,
        }
        values.update(overrides)
        return Settings(**values)

    return make


@pytest_asyncio.fixture
async def engine(database_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(database_url)
    async with eng.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE history_entries, shares, sessions, oauth_accounts, users RESTART IDENTITY CASCADE"
            )
        )
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session


@pytest.fixture
def make_app(settings_factory: Callable[..., Any], engine: AsyncEngine) -> Callable[..., Any]:
    from app.main import create_app

    def factory(**overrides: Any) -> Any:
        return create_app(settings_factory(**overrides))

    return factory


@pytest_asyncio.fixture
async def client(make_app: Callable[..., Any]) -> AsyncIterator[AsyncTestClient[Any]]:
    async with AsyncTestClient(app=make_app(), base_url="http://testserver") as c:
        yield c


@pytest.fixture
def new_client(make_app: Callable[..., Any]) -> Callable[..., Any]:
    """Factory for extra independent clients (another user / anonymous)."""

    def factory(**overrides: Any) -> AsyncTestClient[Any]:
        return AsyncTestClient(app=make_app(**overrides), base_url="http://testserver")

    return factory


async def create_user(
    db: AsyncSession, email: str | None = "user@example.com", name: str = "Test"
) -> Any:
    from app.db.models import User

    user = User(email=email, email_verified=bool(email), name=name)
    db.add(user)
    await db.commit()
    return user


async def create_session(
    db: AsyncSession, user: Any, *, expires_in: timedelta = timedelta(days=1)
) -> str:
    from app.db.models import Session
    from app.lib.security import random_token, token_hash

    raw = random_token(32)
    now = datetime.now(UTC)
    db.add(
        Session(
            user_id=user.id,
            token_hash=token_hash(raw),
            expires_at=now + expires_in,
            last_seen_at=now,
            user_agent="pytest",
        )
    )
    await db.commit()
    return raw


def login(client: AsyncTestClient[Any], raw_token: str) -> str:
    """Attach session + CSRF cookies/header to a test client. Returns the CSRF token."""
    csrf = generate_csrf_token(SECRET)
    client.cookies.set("jv_session", raw_token)
    client.cookies.set("csrftoken", csrf)
    client.headers["X-CSRF-Token"] = csrf
    return csrf


@pytest_asyncio.fixture
async def user(db: AsyncSession) -> Any:
    return await create_user(db)


@pytest_asyncio.fixture
async def auth_client(
    make_app: Callable[..., Any], db: AsyncSession, user: Any
) -> AsyncIterator[AsyncTestClient[Any]]:
    raw = await create_session(db, user)
    async with AsyncTestClient(app=make_app(), base_url="http://testserver") as c:
        login(c, raw)
        yield c


@pytest.fixture
def uid() -> Callable[[], str]:
    return lambda: uuid.uuid4().hex[:8]
